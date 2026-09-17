using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Phân tích một team: role được gán, thành viên, quyền hiệu lực gộp từ các role và app truy cập được.</summary>
public sealed class TeamAnalyzer(DataverseService service)
{
    public async Task<TeamAnalysis> AnalyzeAsync(TeamInfo team, IProgress<string>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();

        progress?.Report("Đang tải metadata entity và privilege...");
        var metadata = await service.GetEntityMetadataAsync(ct);
        var catalog = await service.GetPrivilegeCatalogAsync(ct);

        progress?.Report("Đang tải role của team...");
        var roles = await service.GetTeamRolesAsync(team.Id, ct);

        var privilegesByRole = new Dictionary<Guid, Dictionary<Guid, PrivilegeDepth>>();
        foreach (var role in roles.DistinctBy(r => r.RootRoleId))
        {
            progress?.Report($"Đang tải privilege của role \"{role.Name}\"...");
            privilegesByRole[role.RootRoleId] = await service.GetRolePrivilegesAsync(role.RootRoleId, ct);
        }

        var (entityRows, miscRows) = MergePrivileges(
            catalog,
            roles.DistinctBy(r => r.RootRoleId).Select(r => (r.Name, privilegesByRole[r.RootRoleId])),
            metadata);
        FillRoleStatistics(roles, privilegesByRole, catalog);

        progress?.Report("Đang tải thành viên team...");
        var members = await RoleAnalyzer.TryAsync(() => service.GetTeamMembersAsync(team.Id, ct), [], "thành viên team", warnings);

        progress?.Report("Đang tải Model-driven App...");
        var roleIds = roles.SelectMany(r => new[] { r.AssignedRoleId, r.RootRoleId }).ToHashSet();
        var apps = roleIds.Count == 0
            ? []
            : await RoleAnalyzer.TryAsync(() => service.GetAppsForRoleAsync(roleIds, ct), [], "Model-driven App", warnings);

        var analysis = new TeamAnalysis
        {
            Team = team,
            Roles = roles,
            Members = members,
            EntityRows = entityRows,
            MiscPrivileges = miscRows,
            Apps = apps.Select(a => new RoleComponent
            {
                Category = ComponentCategory.App,
                Id = a.Id,
                Name = a.Name,
                SubType = a.UniqueName,
                AccessReason = "Có role của team được thêm vào app",
                IsDirect = true,
                IsManaged = a.IsManaged,
                State = a.State == 0 ? "Active" : "Inactive",
            }).OrderBy(a => a.Name).ToList(),
            Warnings = warnings,
        };
        analysis.Findings.AddRange(BuildFindings(analysis));
        return analysis;
    }

    /// <summary>Gộp privilege của nhiều role: lấy mức cao nhất và ghi nhận role nào cấp quyền.</summary>
    public static (List<EntityPrivilegeRow> Entities, List<MiscPrivilegeRow> Misc) MergePrivileges(
        IEnumerable<PrivilegeDefinition> catalog,
        IEnumerable<(string RoleName, Dictionary<Guid, PrivilegeDepth> Privileges)> roles,
        IReadOnlyDictionary<string, EntityInfo> metadata)
    {
        var merged = new Dictionary<Guid, PrivilegeDepth>();
        var sources = new Dictionary<Guid, List<string>>();

        foreach (var (roleName, privileges) in roles)
        {
            foreach (var (privilegeId, depth) in privileges)
            {
                if (depth == PrivilegeDepth.None)
                    continue;
                if (!merged.TryGetValue(privilegeId, out var current) || current < depth)
                    merged[privilegeId] = depth;
                if (!sources.TryGetValue(privilegeId, out var list))
                    sources[privilegeId] = list = [];
                list.Add($"{roleName} ({depth.ToText()})");
            }
        }

        return RoleAnalyzer.BuildPrivilegeRows(catalog, merged, metadata, sources);
    }

    private static void FillRoleStatistics(
        List<TeamRoleAssignment> roles,
        Dictionary<Guid, Dictionary<Guid, PrivilegeDepth>> privilegesByRole,
        List<PrivilegeDefinition> catalog)
    {
        var entityByPrivilege = catalog
            .Where(p => p.EntityLogicalName is not null && EntityPrivilegeRow.StandardRights.Contains(p.AccessRight))
            .GroupBy(p => p.Id)
            .ToDictionary(g => g.Key, g => g.First().EntityLogicalName!);

        foreach (var role in roles)
        {
            if (!privilegesByRole.TryGetValue(role.RootRoleId, out var privileges))
                continue;
            var granted = privileges.Where(p => p.Value > PrivilegeDepth.None).Select(p => p.Key).ToList();
            role.GrantedEntityCount = granted.Where(entityByPrivilege.ContainsKey).Select(id => entityByPrivilege[id]).Distinct().Count();
            role.GrantedMiscCount = granted.Count(id => !entityByPrivilege.ContainsKey(id));
        }
    }

    public static IEnumerable<AnalysisFinding> BuildFindings(TeamAnalysis analysis)
    {
        var team = analysis.Team;

        if (analysis.Roles.Count == 0)
        {
            yield return team.TeamType == 0
                ? new AnalysisFinding
                {
                    Severity = FindingSeverity.Medium,
                    Title = "Owner team chưa có security role",
                    Detail = "Team không thể sở hữu bản ghi và thành viên không nhận thêm quyền nào từ team.",
                }
                : new AnalysisFinding
                {
                    Severity = FindingSeverity.Info,
                    Title = "Team chưa có security role",
                    Detail = "Thành viên không nhận thêm quyền nào từ team.",
                };
        }

        if (TeamTypes.IsEntraGroup(team.TeamType))
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "Thành viên được đồng bộ từ Microsoft Entra ID",
                Detail = $"Quản lý thành viên trong nhóm Entra ID (Object Id: {team.EntraObjectId}). Danh sách chỉ gồm user đã từng truy cập môi trường.",
            };
        }

        if (team.IsDefault)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "Default team của Business Unit",
                Detail = "Mọi user thuộc BU tự động là thành viên – role gán cho team này áp dụng cho toàn bộ user của BU.",
            };
        }

        if (analysis.Roles.Count > 0 && analysis.Members.Count == 0 && !TeamTypes.IsEntraGroup(team.TeamType))
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Low,
                Title = "Team có role nhưng chưa có thành viên",
                Detail = "Role đang gán không có hiệu lực với user nào.",
            };
        }

        var disabled = analysis.Members.Where(m => m.IsDisabled).ToList();
        if (disabled.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Low,
                Title = $"{disabled.Count} thành viên đã disabled",
                Detail = RoleAnalyzer.Names(disabled.Select(m => m.FullName)),
            };
        }

        foreach (var finding in RoleAnalyzer.BuildPrivilegeFindings(analysis.EntityRows, analysis.MiscPrivileges))
        {
            yield return new AnalysisFinding
            {
                Severity = finding.Severity,
                Title = finding.Title,
                Detail = finding.Detail + $"  (áp dụng cho {analysis.Members.Count} thành viên)",
            };
        }

        if (analysis.Roles.Count > 0 && analysis.Apps.Count == 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "Không role nào của team được thêm vào Model-driven App",
                Detail = "Thành viên cần role khác (gán trực tiếp) để mở app.",
            };
        }
    }
}
