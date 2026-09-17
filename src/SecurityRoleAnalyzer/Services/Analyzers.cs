using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Quyền hiệu lực của một user: role trực tiếp + role qua team, team, app, field security profile.</summary>
public sealed class UserAnalyzer(DataverseService service)
{
    public async Task<UserAnalysis> AnalyzeAsync(UserInfo user, IProgress<string>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();

        progress?.Report("Đang tải metadata entity và privilege...");
        var metadata = await service.GetEntityMetadataAsync(ct);
        var catalog = await service.GetPrivilegeCatalogAsync(ct);

        progress?.Report("Đang tải role và team của user...");
        var direct = await service.GetUserDirectRolesAsync(user.Id, ct);
        var teams = await service.GetUserTeamsAsync(user.Id, ct);
        var teamRoles = await service.GetRolesOfTeamsAsync(teams, ct);
        foreach (var team in teams)
            team.RoleCount = teamRoles.Count(r => r.TeamId == team.Id);

        var all = direct.Concat(teamRoles).ToList();
        foreach (var group in all.GroupBy(r => r.RootRoleId).Where(g => g.Count() > 1))
        foreach (var role in group)
            role.IsDuplicated = true;

        var privilegesByRole = new Dictionary<Guid, Dictionary<Guid, PrivilegeDepth>>();
        foreach (var role in all.DistinctBy(r => r.RootRoleId))
        {
            progress?.Report($"Đang tải privilege của role \"{role.Name}\"...");
            privilegesByRole[role.RootRoleId] = await service.GetRolePrivilegesAsync(role.RootRoleId, ct);
        }

        var (entityRows, miscRows) = TeamAnalyzer.MergePrivileges(
            catalog,
            all.Select(r => (SourceLabel(r), privilegesByRole[r.RootRoleId])),
            metadata);

        progress?.Report("Đang tải app và field security profile...");
        var roleIds = all.SelectMany(r => new[] { r.AssignedRoleId, r.RootRoleId }).ToHashSet();
        var apps = roleIds.Count == 0
            ? []
            : await RoleAnalyzer.TryAsync(() => service.GetAppsForRoleAsync(roleIds, ct), [], "Model-driven App", warnings);
        var profiles = await RoleAnalyzer.TryAsync(() => service.GetFieldProfilesOfUserAsync(user.Id, teams, ct), [], "Field Security Profile", warnings);

        var analysis = new UserAnalysis
        {
            User = user,
            DirectRoles = direct,
            Teams = teams,
            TeamRoles = teamRoles,
            EntityRows = entityRows,
            MiscPrivileges = miscRows,
            Apps = apps.Select(a => new RoleComponent
            {
                Category = ComponentCategory.App,
                Id = a.Id,
                Name = a.Name,
                SubType = a.UniqueName,
                IsDirect = true,
                IsManaged = a.IsManaged,
                State = a.State == 0 ? "Active" : "Inactive",
            }).OrderBy(a => a.Name).ToList(),
            FieldProfiles = profiles,
            Warnings = warnings,
        };
        analysis.Findings.AddRange(BuildFindings(analysis));
        return analysis;
    }

    public static string SourceLabel(UserRoleAssignment role) => role.IsDirect ? role.Name : $"{role.Name} [team {role.TeamName}]";

    public static bool IsSystemAdministrator(string roleName) =>
        roleName.Equals("System Administrator", StringComparison.OrdinalIgnoreCase)
        || roleName.Equals("Quản trị viên hệ thống", StringComparison.OrdinalIgnoreCase);

    public static IEnumerable<AnalysisFinding> BuildFindings(UserAnalysis analysis)
    {
        var user = analysis.User;
        var roles = analysis.AllRoles.ToList();

        if (roles.Count == 0 && !user.IsDisabled)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.High,
                Title = "User không có security role nào",
                Detail = "User không thể truy cập ứng dụng. Hãy gán role trực tiếp hoặc thêm vào team có role.",
            };
        }

        if (user.IsDisabled && roles.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Low,
                Title = "User đã disabled nhưng vẫn còn role",
                Detail = $"{analysis.DirectRoles.Count} role trực tiếp, {analysis.Teams.Count} team – nên dọn dẹp.",
            };
        }

        var admin = roles.Where(r => IsSystemAdministrator(r.Name)).ToList();
        if (admin.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Medium,
                Title = "User có role System Administrator",
                Detail = "Toàn quyền trên môi trường – nguồn: " + string.Join(", ", admin.Select(r => r.SourceText)),
            };
        }

        var duplicated = roles.Where(r => r.IsDuplicated).GroupBy(r => r.RootRoleId).ToList();
        if (duplicated.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = $"{duplicated.Count} role được nhận từ nhiều nguồn",
                Detail = string.Join("; ", duplicated.Select(g => $"{g.First().Name}: {string.Join(", ", g.Select(r => r.SourceText))}")),
            };
        }

        if (user.IsApplicationUser)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "Application user (tích hợp)",
                Detail = "Tài khoản dành cho ứng dụng/tích hợp – rà soát kỹ quyền vì không có MFA.",
            };
        }

        foreach (var finding in RoleAnalyzer.BuildPrivilegeFindings(analysis.EntityRows, analysis.MiscPrivileges))
            yield return finding;

        if (roles.Count > 0 && analysis.Apps.Count == 0 && admin.Count == 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "User không mở được Model-driven App nào",
                Detail = "Không role nào của user được thêm vào app.",
            };
        }
    }
}

/// <summary>Phân tích Model-driven App: role được thêm vào app và user hiệu lực.</summary>
public static class AppAnalyzer
{
    public static AppAnalysis Analyze(AppModuleInfo app, IReadOnlyCollection<(Guid AppId, Guid RoleId)> links, AccessIndex index)
    {
        var roleIds = links
            .Where(l => l.AppId == app.Id || l.AppId == app.UniqueId)
            .Select(l => index.CopyToRoot.GetValueOrDefault(l.RoleId, l.RoleId))
            .Distinct()
            .ToList();

        var roles = roleIds.Select(id =>
        {
            var info = index.RoleById.GetValueOrDefault(id);
            return new AppRoleRow
            {
                RoleId = id,
                Name = info?.Name ?? id.ToString(),
                IsManaged = info?.IsManaged ?? false,
                DirectUserCount = index.UsersWithDirectRole(id).Distinct().Count(),
                TeamCount = index.TeamsWithRole(id).Distinct().Count(),
                EffectiveUserCount = index.EffectiveUsersOf(id).Select(u => u.UserId).Distinct().Count(),
            };
        }).OrderBy(r => r.Name).ToList();

        var users = roleIds
            .SelectMany(roleId => index.EffectiveUsersOf(roleId).Select(u => (u.UserId, Via: u.TeamId is { } t
                ? $"{index.RoleName(roleId)} (team {index.TeamName(t)})"
                : index.RoleName(roleId))))
            .GroupBy(x => x.UserId)
            .Select(g =>
            {
                var user = index.UserById.GetValueOrDefault(g.Key);
                return new PrincipalAccessRow
                {
                    Id = g.Key,
                    Name = user?.FullName ?? g.Key.ToString(),
                    Detail = user?.DomainName ?? "",
                    BusinessUnitName = user?.BusinessUnitName ?? "",
                    IsDisabled = user?.IsDisabled ?? false,
                    Via = string.Join(", ", g.Select(x => x.Via).Distinct()),
                };
            })
            .OrderBy(u => u.Name)
            .ToList();

        var findings = new List<AnalysisFinding>();
        if (roles.Count == 0)
        {
            findings.Add(new AnalysisFinding
            {
                Severity = FindingSeverity.Medium,
                Title = "App chưa được gán role nào",
                Detail = "Chỉ System Administrator / System Customizer mở được app.",
            });
        }
        var disabled = users.Count(u => u.IsDisabled);
        if (disabled > 0)
        {
            findings.Add(new AnalysisFinding
            {
                Severity = FindingSeverity.Low,
                Title = $"{disabled} user disabled vẫn có role của app",
                Detail = RoleAnalyzer.Names(users.Where(u => u.IsDisabled).Select(u => u.Name)),
            });
        }
        foreach (var role in roles.Where(r => r.EffectiveUserCount == 0))
        {
            findings.Add(new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = $"Role \"{role.Name}\" không có user nào",
                Detail = "Role được thêm vào app nhưng chưa gán cho user/team nào.",
            });
        }

        return new AppAnalysis { App = app, Roles = roles, Users = users, Findings = findings };
    }
}

public static class FieldProfileAnalyzer
{
    public static async Task<FieldProfileAnalysis> AnalyzeAsync(DataverseService service, FieldSecurityProfileInfo profile, CancellationToken ct)
    {
        var users = await service.GetFieldProfileUsersAsync(profile.Id, ct);
        var teams = await service.GetFieldProfileTeamsAsync(profile.Id, ct);
        var permissions = await service.GetFieldPermissionsAsync(profile.Id, ct);

        var effective = users.Select(u => new PrincipalAccessRow
        {
            Id = u.Id, Name = u.FullName, Detail = u.DomainName, BusinessUnitName = u.BusinessUnitName, IsDisabled = u.IsDisabled, Via = "Trực tiếp",
        }).ToList();
        foreach (var team in teams)
        {
            foreach (var member in await service.GetTeamMembersAsync(team.Id, ct))
            {
                effective.Add(new PrincipalAccessRow
                {
                    Id = member.Id, Name = member.FullName, Detail = member.DomainName, BusinessUnitName = member.BusinessUnitName,
                    IsDisabled = member.IsDisabled, Via = $"Team {team.Name}",
                });
            }
        }
        effective = effective
            .GroupBy(e => e.Id)
            .Select(g => new PrincipalAccessRow
            {
                Id = g.Key, Name = g.First().Name, Detail = g.First().Detail, BusinessUnitName = g.First().BusinessUnitName,
                IsDisabled = g.First().IsDisabled, Via = string.Join(", ", g.Select(x => x.Via).Distinct()),
            })
            .OrderBy(e => e.Name)
            .ToList();

        var findings = new List<AnalysisFinding>();
        if (users.Count == 0 && teams.Count == 0)
            findings.Add(new AnalysisFinding { Severity = FindingSeverity.Info, Title = "Profile chưa gán cho user/team nào", Detail = "Có thể là profile không còn sử dụng." });
        if (permissions.Count == 0)
            findings.Add(new AnalysisFinding { Severity = FindingSeverity.Info, Title = "Profile chưa có field permission nào", Detail = "User thuộc profile không nhận thêm quyền trên cột bảo mật." });
        var updateAll = permissions.Count(p => p.CanRead && p.CanCreate && p.CanUpdate);
        if (updateAll > 0)
            findings.Add(new AnalysisFinding { Severity = FindingSeverity.Low, Title = $"{updateAll} cột được cấp đủ Read/Create/Update", Detail = RoleAnalyzer.Names(permissions.Where(p => p.CanRead && p.CanCreate && p.CanUpdate).Select(p => $"{p.EntityDisplayName}.{p.AttributeDisplayName}")) });
        var disabled = effective.Count(e => e.IsDisabled);
        if (disabled > 0)
            findings.Add(new AnalysisFinding { Severity = FindingSeverity.Low, Title = $"{disabled} user disabled vẫn thuộc profile", Detail = RoleAnalyzer.Names(effective.Where(e => e.IsDisabled).Select(e => e.Name)) });

        return new FieldProfileAnalysis
        {
            Profile = profile,
            Users = users,
            Teams = teams,
            EffectiveUsers = effective,
            Permissions = permissions,
            Findings = findings,
        };
    }
}

public static class BusinessUnitAnalyzer
{
    /// <summary>Dựng cây BU kèm số user/team của từng BU.</summary>
    public static List<BusinessUnitNode> BuildTree(AccessIndex index)
    {
        var nodes = new Dictionary<Guid, BusinessUnitNode>();
        var ids = index.BusinessUnits.Select(b => b.Id).ToHashSet();
        var users = index.Users.GroupBy(u => u.BusinessUnitId).ToDictionary(g => g.Key, g => g.Count());
        var teams = index.Teams.GroupBy(t => t.BusinessUnitId).ToDictionary(g => g.Key, g => g.Count());

        BusinessUnitNode Create(BusinessUnitInfo unit, BusinessUnitNode? parent)
        {
            var node = new BusinessUnitNode
            {
                Unit = unit,
                Parent = parent,
                UserCount = users.GetValueOrDefault(unit.Id),
                TeamCount = teams.GetValueOrDefault(unit.Id),
                IsExpanded = parent is null,
            };
            nodes[unit.Id] = node;
            foreach (var child in index.BusinessUnits.Where(b => b.ParentId == unit.Id).OrderBy(b => b.Name))
                node.Children.Add(Create(child, node));
            return node;
        }

        return index.BusinessUnits
            .Where(b => b.ParentId is null || !ids.Contains(b.ParentId.Value))
            .OrderBy(b => b.Name)
            .Select(b => Create(b, null))
            .ToList();
    }

    public static BusinessUnitAnalysis Analyze(BusinessUnitNode node, AccessIndex index)
    {
        var users = index.Users.Where(u => u.BusinessUnitId == node.Unit.Id).OrderBy(u => u.FullName).ToList();
        var teams = index.Teams.Where(t => t.BusinessUnitId == node.Unit.Id).OrderBy(t => t.Name).ToList();
        var subtree = node.DescendantsAndSelf().ToList();

        var usage = users
            .SelectMany(u => index.EffectiveRolesOf(u.Id).Select(r => (u.Id, r.RoleId, r.TeamId)))
            .GroupBy(x => x.RoleId)
            .Select(g => new RoleUsageRow
            {
                RoleId = g.Key,
                Name = index.RoleName(g.Key),
                DirectUserCount = g.Where(x => x.TeamId is null).Select(x => x.Id).Distinct().Count(),
                TeamUserCount = g.Where(x => x.TeamId is not null).Select(x => x.Id).Distinct().Count(),
                TotalUserCount = g.Select(x => x.Id).Distinct().Count(),
            })
            .OrderByDescending(r => r.TotalUserCount)
            .ThenBy(r => r.Name)
            .ToList();

        var findings = new List<AnalysisFinding>();
        var noRole = users.Where(u => !u.IsDisabled && !index.EffectiveRolesOf(u.Id).Any()).ToList();
        if (noRole.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                Severity = FindingSeverity.Medium,
                Title = $"{noRole.Count} user đang hoạt động không có role nào",
                Detail = RoleAnalyzer.Names(noRole.Select(u => u.FullName)),
            });
        }
        if (node.Unit.IsDisabled && users.Any(u => !u.IsDisabled))
        {
            findings.Add(new AnalysisFinding
            {
                Severity = FindingSeverity.Medium,
                Title = "BU đã disabled nhưng còn user đang hoạt động",
                Detail = $"{users.Count(u => !u.IsDisabled)} user.",
            });
        }
        var disabledWithRoles = users.Where(u => u.IsDisabled && index.DirectRolesOf(u.Id).Any()).ToList();
        if (disabledWithRoles.Count > 0)
        {
            findings.Add(new AnalysisFinding
            {
                Severity = FindingSeverity.Low,
                Title = $"{disabledWithRoles.Count} user disabled còn role",
                Detail = RoleAnalyzer.Names(disabledWithRoles.Select(u => u.FullName)),
            });
        }

        var subtreeUsers = subtree.Sum(n => n.UserCount);
        var scope =
            $"• Mức User: chỉ bản ghi user/team của user sở hữu hoặc được chia sẻ.\n" +
            $"• Mức Business Unit: bản ghi thuộc BU \"{node.Unit.Name}\" ({users.Count} user, {teams.Count} team).\n" +
            $"• Mức Parent: Child BU: bản ghi của {subtree.Count} BU (BU này và {subtree.Count - 1} BU con) – {subtreeUsers} user.\n" +
            $"• Mức Organization: toàn bộ {index.BusinessUnits.Count} BU – {index.Users.Count} user.";

        return new BusinessUnitAnalysis
        {
            Node = node,
            Users = users,
            Teams = teams,
            Children = node.Children.Select(c => c.Unit).ToList(),
            RoleUsage = usage,
            Findings = findings,
            ScopeText = scope,
        };
    }
}

/// <summary>Rà soát quyền toàn hệ thống (User × Role).</summary>
public static class AccessReviewBuilder
{
    public static (List<ReviewUserRow> Users, List<ReviewRoleRow> Roles) Build(AccessIndex index)
    {
        var users = index.Users.Select(user =>
        {
            var direct = index.DirectRolesOf(user.Id).Distinct().ToList();
            var viaTeam = index.EffectiveRolesOf(user.Id).Where(r => r.TeamId is not null).ToList();
            var effective = direct.Concat(viaTeam.Select(r => r.RoleId)).Distinct().ToList();
            var isAdmin = effective.Any(id => UserAnalyzer.IsSystemAdministrator(index.RoleName(id)));

            var flags = new List<string>();
            if (effective.Count == 0 && !user.IsDisabled) flags.Add("Không có role");
            if (user.IsDisabled && direct.Count > 0) flags.Add("Disabled còn role");
            if (isAdmin) flags.Add("System Administrator");
            if (direct.Intersect(viaTeam.Select(r => r.RoleId)).Any()) flags.Add("Role trùng (trực tiếp + team)");
            if (user.IsApplicationUser) flags.Add("Application user");

            return new ReviewUserRow
            {
                User = user,
                DirectRoles = string.Join(", ", direct.Select(index.RoleName).Order()),
                TeamRoles = string.Join(", ", viaTeam.Select(r => $"{index.RoleName(r.RoleId)} ({index.TeamName(r.TeamId!.Value)})").Distinct().Order()),
                DirectRoleCount = direct.Count,
                TeamRoleCount = viaTeam.Select(r => r.RoleId).Distinct().Count(),
                EffectiveRoleCount = effective.Count,
                TeamCount = index.TeamsOf(user.Id).Distinct().Count(),
                IsSystemAdministrator = isAdmin,
                Flags = string.Join(" · ", flags),
            };
        }).OrderBy(r => r.User.FullName).ToList();

        var roles = index.Roles.Select(role =>
        {
            var effective = index.EffectiveUsersOf(role.Id).Select(u => u.UserId).Distinct().ToList();
            return new ReviewRoleRow
            {
                Role = role,
                DirectUserCount = index.UsersWithDirectRole(role.Id).Distinct().Count(),
                TeamCount = index.TeamsWithRole(role.Id).Distinct().Count(),
                EffectiveUserCount = effective.Count,
                DisabledUserCount = effective.Count(id => index.UserById.GetValueOrDefault(id)?.IsDisabled == true),
            };
        }).OrderBy(r => r.Role.Name).ToList();

        return (users, roles);
    }
}

/// <summary>Tra ngược: ai có một privilege ở mức tối thiểu nào đó.</summary>
public static class AccessLookup
{
    public static (List<LookupRoleRow> Roles, List<PrincipalAccessRow> Teams, List<PrincipalAccessRow> Users) Find(
        AccessIndex index, PrivilegeDefinition privilege, PrivilegeDepth minimumDepth)
    {
        var min = minimumDepth == PrivilegeDepth.None ? PrivilegeDepth.User : minimumDepth;

        var roles = index.Roles
            .Select(r => (Role: r, Depth: index.DepthOf(r.Id, privilege.Id)))
            .Where(x => x.Depth >= min)
            .Select(x => new LookupRoleRow
            {
                RoleId = x.Role.Id,
                Name = x.Role.Name,
                IsManaged = x.Role.IsManaged,
                Depth = x.Depth,
                DirectUserCount = index.UsersWithDirectRole(x.Role.Id).Distinct().Count(),
                TeamCount = index.TeamsWithRole(x.Role.Id).Distinct().Count(),
            })
            .OrderByDescending(r => r.Depth)
            .ThenBy(r => r.Name)
            .ToList();
        var roleDepth = roles.ToDictionary(r => r.RoleId, r => r.Depth);

        var teams = roles
            .SelectMany(r => index.TeamsWithRole(r.RoleId).Select(t => (TeamId: t, r.RoleId)))
            .GroupBy(x => x.TeamId)
            .Select(g =>
            {
                var team = index.TeamById.GetValueOrDefault(g.Key);
                return new PrincipalAccessRow
                {
                    Type = "Team",
                    Id = g.Key,
                    Name = team?.Name ?? g.Key.ToString(),
                    Detail = team?.TeamTypeText ?? "",
                    BusinessUnitName = team?.BusinessUnitName ?? "",
                    Depth = g.Max(x => roleDepth[x.RoleId]),
                    Via = string.Join(", ", g.Select(x => index.RoleName(x.RoleId)).Distinct()),
                };
            })
            .OrderByDescending(t => t.Depth)
            .ThenBy(t => t.Name)
            .ToList();

        var users = roles
            .SelectMany(r => index.EffectiveUsersOf(r.RoleId).Select(u => (u.UserId, u.TeamId, r.RoleId)))
            .GroupBy(x => x.UserId)
            .Select(g =>
            {
                var user = index.UserById.GetValueOrDefault(g.Key);
                return new PrincipalAccessRow
                {
                    Id = g.Key,
                    Name = user?.FullName ?? g.Key.ToString(),
                    Detail = user?.DomainName ?? "",
                    BusinessUnitName = user?.BusinessUnitName ?? "",
                    IsDisabled = user?.IsDisabled ?? false,
                    Depth = g.Max(x => roleDepth[x.RoleId]),
                    Via = string.Join(", ", g.Select(x => x.TeamId is { } t
                        ? $"{index.RoleName(x.RoleId)} (team {index.TeamName(t)})"
                        : index.RoleName(x.RoleId)).Distinct()),
                };
            })
            .OrderByDescending(u => u.Depth)
            .ThenBy(u => u.Name)
            .ToList();

        return (roles, teams, users);
    }
}
