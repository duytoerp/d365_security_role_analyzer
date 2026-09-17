using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Tổng hợp dữ liệu từ Dataverse thành kết quả phân tích cho một security role.</summary>
public sealed class RoleAnalyzer(DataverseService service)
{
    private static readonly string[] SensitiveEntities =
    [
        "role", "systemuser", "team", "businessunit", "fieldsecurityprofile", "fieldpermission",
        "pluginassembly", "plugintype", "sdkmessageprocessingstep", "sdkmessageprocessingstepimage",
        "solution", "workflow", "customapi", "environmentvariablevalue", "connectionreference",
        "organization", "audit", "position", "hierarchysecurityconfiguration",
    ];

    private static readonly Dictionary<string, string> SensitiveMiscPrivileges = new(StringComparer.OrdinalIgnoreCase)
    {
        ["prvBulkDelete"] = "Xóa hàng loạt dữ liệu (Bulk Delete)",
        ["prvExportToExcel"] = "Xuất dữ liệu ra Excel",
        ["prvPublishCustomization"] = "Publish customization",
        ["prvImportCustomization"] = "Import solution / customization",
        ["prvExportCustomization"] = "Export solution / customization",
        ["prvActOnBehalfOfAnotherUser"] = "Impersonate (thực thi thay user khác)",
        ["prvBypassCustomPlugins"] = "Bỏ qua plugin tùy chỉnh",
        ["prvBypassCustomPluginExecution"] = "Bỏ qua thực thi plugin tùy chỉnh",
        ["prvBypassCustomBusinessLogic"] = "Bỏ qua business logic tùy chỉnh",
        ["prvDeleteAuditPartitions"] = "Xóa lịch sử audit",
        ["prvDeleteRecordChangeHistory"] = "Xóa lịch sử thay đổi bản ghi",
        ["prvReadAuditSummary"] = "Xem audit summary",
        ["prvReassignAll"] = "Chuyển toàn bộ bản ghi sang user khác",
        ["prvDisableBusinessUnit"] = "Vô hiệu hóa Business Unit",
    };

    public async Task<RoleAnalysis> AnalyzeAsync(SecurityRoleInfo role, IProgress<string>? progress, CancellationToken ct)
    {
        var warnings = new List<string>();

        progress?.Report("Đang tải metadata entity...");
        var metadata = await service.GetEntityMetadataAsync(ct);

        progress?.Report("Đang tải danh mục privilege...");
        var catalog = await service.GetPrivilegeCatalogAsync(ct);

        progress?.Report("Đang tải privilege của role...");
        var rolePrivileges = await service.GetRolePrivilegesAsync(role.Id, ct);
        var copies = await service.GetRoleCopiesAsync(role, ct);
        var roleIds = copies.Select(c => c.RoleId).ToHashSet();

        var (entityRows, miscRows) = BuildPrivilegeRows(catalog, rolePrivileges, metadata);

        progress?.Report("Đang tải user được gán role...");
        var users = await service.GetRoleUsersAsync(roleIds, ct);

        progress?.Report("Đang tải team được gán role...");
        var teams = await service.GetRoleTeamsAsync(roleIds, ct);

        progress?.Report("Đang tải thành viên team...");
        var teamUsers = await TryAsync(() => service.GetTeamMembersAsync(teams, ct), [], "thành viên team", warnings);
        LinkUsersAndTeams(users, teams, teamUsers);

        progress?.Report("Đang phân tích component (App, Form, View...)...");
        var components = await BuildComponentsAsync(roleIds, entityRows, catalog, rolePrivileges, metadata, warnings, ct);

        var analysis = new RoleAnalysis
        {
            Role = role,
            RoleCopies = copies,
            EntityRows = entityRows,
            MiscPrivileges = miscRows,
            Users = users,
            Teams = teams,
            TeamUsers = teamUsers,
            Components = components,
            Warnings = warnings,
        };
        analysis.Findings.AddRange(BuildFindings(analysis));
        return analysis;
    }

    public static (List<EntityPrivilegeRow> Entities, List<MiscPrivilegeRow> Misc) BuildPrivilegeRows(
        IEnumerable<PrivilegeDefinition> catalog,
        IReadOnlyDictionary<Guid, PrivilegeDepth> rolePrivileges,
        IReadOnlyDictionary<string, EntityInfo> metadata,
        IReadOnlyDictionary<Guid, List<string>>? sourceRoles = null)
    {
        var rows = new Dictionary<string, EntityPrivilegeRow>(StringComparer.OrdinalIgnoreCase);
        var misc = new List<MiscPrivilegeRow>();

        foreach (var privilege in catalog)
        {
            var depth = rolePrivileges.GetValueOrDefault(privilege.Id, PrivilegeDepth.None);
            IReadOnlyList<string> sources = sourceRoles?.GetValueOrDefault(privilege.Id) ?? [];

            if (privilege.EntityLogicalName is { } entityName)
            {
                if (!rows.TryGetValue(entityName, out var row))
                {
                    var info = metadata.GetValueOrDefault(entityName);
                    row = new EntityPrivilegeRow
                    {
                        LogicalName = entityName,
                        DisplayName = info?.DisplayName ?? entityName,
                        IsCustom = info?.IsCustom ?? false,
                    };
                    rows[entityName] = row;
                }

                var cell = new PrivilegeCell
                {
                    Definition = privilege,
                    PrivilegeName = privilege.Name,
                    Depth = depth,
                    OriginalDepth = depth,
                    AllowedDepths = privilege.AllowedDepthsText,
                    SourceRoles = sources,
                };
                if (row.TrySet(privilege.AccessRight, cell))
                    continue;
            }

            misc.Add(new MiscPrivilegeRow
            {
                Definition = privilege,
                Name = privilege.Name,
                Entity = privilege.EntityLogicalName ?? "",
                Depth = depth,
                OriginalDepth = depth,
                AllowedDepths = privilege.AllowedDepthsText,
                SourceRoles = sources,
            });
        }

        return (
            rows.Values.OrderBy(r => r.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToList(),
            misc.DistinctBy(m => (m.Name, m.Entity)).OrderBy(m => m.Name).ToList());
    }

    private static void LinkUsersAndTeams(List<RoleUser> users, List<RoleTeam> teams, List<RoleTeamUser> teamUsers)
    {
        var directIds = users.Select(u => u.Id).ToHashSet();
        var viaTeamIds = teamUsers.Select(u => u.UserId).ToHashSet();

        foreach (var user in users)
            user.AlsoViaTeam = viaTeamIds.Contains(user.Id);
        foreach (var member in teamUsers)
            member.AlsoDirect = directIds.Contains(member.UserId);

        var counts = teamUsers.GroupBy(t => t.TeamId).ToDictionary(g => g.Key, g => g.Count());
        foreach (var team in teams)
            team.MemberCount = counts.GetValueOrDefault(team.Id);
    }

    private async Task<List<RoleComponent>> BuildComponentsAsync(
        HashSet<Guid> roleIds,
        List<EntityPrivilegeRow> entityRows,
        List<PrivilegeDefinition> catalog,
        Dictionary<Guid, PrivilegeDepth> rolePrivileges,
        Dictionary<string, EntityInfo> metadata,
        List<string> warnings,
        CancellationToken ct)
    {
        var components = new List<RoleComponent>();
        var readDepth = entityRows
            .Where(r => r.Read.Depth > PrivilegeDepth.None)
            .ToDictionary(r => r.LogicalName, r => r.Read.Depth, StringComparer.OrdinalIgnoreCase);

        string DisplayOf(string logicalName) =>
            metadata.TryGetValue(logicalName, out var info) ? info.DisplayName : logicalName;

        // Model-driven apps: gán trực tiếp qua appmoduleroles.
        var apps = await TryAsync(() => service.GetAppsForRoleAsync(roleIds, ct), [], "Model-driven App", warnings);
        components.AddRange(apps.Select(a => new RoleComponent
        {
            Category = ComponentCategory.App,
            Id = a.Id,
            Name = a.Name,
            SubType = a.UniqueName,
            AccessReason = "Role được thêm vào app (App security roles)",
            IsDirect = true,
            IsManaged = a.IsManaged,
            State = a.State == 0 ? "Active" : "Inactive",
        }));

        // Forms & dashboards: displayconditions.
        var forms = await TryAsync(() => service.GetFormsAsync(ct), [], "Form/Dashboard", warnings);
        foreach (var form in forms)
        {
            var isDashboard = form.Type is 0 or 10 or 103;
            var assigned = form.RoleIds.Overlaps(roleIds);
            var roleAssignable = form.Type is 0 or 2 or 10 or 12 or 103;
            var entityReadable = form.Entity == "none" || readDepth.ContainsKey(form.Entity);

            string reason;
            if (assigned)
                reason = "Form được gán trực tiếp cho role (Form Order / Assign Security Roles)";
            else if (!entityReadable)
                continue;
            else if (!roleAssignable)
                reason = "Loại form không phân quyền theo role – truy cập theo quyền Read entity";
            else if (form.VisibleToEveryone)
                reason = "Form hiển thị cho mọi role (Display to everyone)";
            else
                continue;

            components.Add(new RoleComponent
            {
                Category = isDashboard ? ComponentCategory.Dashboard : ComponentCategory.Form,
                Id = form.Id,
                Name = form.Name,
                EntityLogicalName = form.Entity == "none" ? "" : form.Entity,
                EntityDisplayName = form.Entity == "none" ? "" : DisplayOf(form.Entity),
                SubType = FormTypeText(form.Type),
                AccessReason = reason,
                IsDirect = assigned,
                IsManaged = form.IsManaged,
                State = form.ActivationState == 1 ? "Active" : "Inactive",
            });
        }

        // Views & charts: không phân quyền theo role, phụ thuộc quyền Read của entity.
        var views = await TryAsync(() => service.GetViewsAsync(ct), [], "View", warnings);
        foreach (var view in views)
        {
            if (!readDepth.TryGetValue(view.Entity, out var depth))
                continue;
            components.Add(new RoleComponent
            {
                Category = ComponentCategory.View,
                Id = view.Id,
                Name = view.Name,
                EntityLogicalName = view.Entity,
                EntityDisplayName = DisplayOf(view.Entity),
                SubType = ViewTypeText(view.QueryType) + (view.IsDefault ? " (mặc định)" : ""),
                AccessReason = $"Có quyền Read entity – thấy dữ liệu mức {depth.ToText()}",
                IsManaged = view.IsManaged,
                State = view.State == 0 ? "Active" : "Inactive",
            });
        }

        var charts = await TryAsync(() => service.GetChartsAsync(ct), [], "Chart", warnings);
        foreach (var chart in charts)
        {
            if (!readDepth.TryGetValue(chart.Entity, out var depth))
                continue;
            components.Add(new RoleComponent
            {
                Category = ComponentCategory.Chart,
                Id = chart.Id,
                Name = chart.Name,
                EntityLogicalName = chart.Entity,
                EntityDisplayName = DisplayOf(chart.Entity),
                SubType = "System chart",
                AccessReason = $"Có quyền Read entity – mức {depth.ToText()}",
                IsManaged = chart.IsManaged,
                State = "Active",
            });
        }

        // Business process flow: quyền nằm trên entity BPF (uniquename của workflow).
        var rows = entityRows.ToDictionary(r => r.LogicalName, StringComparer.OrdinalIgnoreCase);
        var bpfs = await TryAsync(() => service.GetBusinessProcessFlowsAsync(ct), [], "Business Process Flow", warnings);
        foreach (var bpf in bpfs)
        {
            if (!rows.TryGetValue(bpf.UniqueName, out var row) || !row.HasAnyPrivilege)
                continue;
            components.Add(new RoleComponent
            {
                Category = ComponentCategory.BusinessProcessFlow,
                Id = bpf.Id,
                Name = bpf.Name,
                EntityLogicalName = bpf.PrimaryEntity,
                EntityDisplayName = DisplayOf(bpf.PrimaryEntity),
                SubType = bpf.UniqueName,
                AccessReason = $"Có privilege trên BPF entity – Read: {row.Read.Depth.ToText()}, Create: {row.Create.Depth.ToText()}, Write: {row.Write.Depth.ToText()}",
                IsDirect = true,
                IsManaged = bpf.IsManaged,
                State = bpf.State == 1 ? "Activated" : "Draft",
            });
        }

        // Custom API có ExecutePrivilegeName.
        var grantedNames = catalog
            .Where(p => rolePrivileges.GetValueOrDefault(p.Id) > PrivilegeDepth.None)
            .Select(p => p.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var apis = await TryAsync(() => service.GetCustomApisAsync(ct), [], "Custom API", warnings);
        foreach (var api in apis.Where(a => grantedNames.Contains(a.ExecutePrivilegeName)))
        {
            components.Add(new RoleComponent
            {
                Category = ComponentCategory.CustomApi,
                Id = api.Id,
                Name = api.Name,
                EntityLogicalName = api.BoundEntity,
                EntityDisplayName = string.IsNullOrEmpty(api.BoundEntity) ? "" : DisplayOf(api.BoundEntity),
                SubType = api.UniqueName,
                AccessReason = $"Role có privilege {api.ExecutePrivilegeName}",
                IsDirect = true,
                IsManaged = api.IsManaged,
                State = "Active",
            });
        }

        return components
            .OrderBy(c => Array.IndexOf(ComponentCategory.All, c.Category))
            .ThenByDescending(c => c.IsDirect)
            .ThenBy(c => c.EntityDisplayName)
            .ThenBy(c => c.Name)
            .ToList();
    }

    internal static string Names(IEnumerable<string> names, int max = 15)
    {
        var list = names.ToList();
        var text = string.Join(", ", list.Take(max));
        return list.Count > max ? $"{text}, ... (+{list.Count - max})" : text;
    }

    /// <summary>Các phát hiện rủi ro dựa trên privilege (dùng chung cho role và quyền hiệu lực của team).</summary>
    public static IEnumerable<AnalysisFinding> BuildPrivilegeFindings(
        IEnumerable<EntityPrivilegeRow> entityRows, IEnumerable<MiscPrivilegeRow> miscPrivileges)
    {
        var granted = entityRows.Where(r => r.HasAnyPrivilege).ToList();

        var sensitive = granted
            .Where(r => SensitiveEntities.Contains(r.LogicalName, StringComparer.OrdinalIgnoreCase))
            .Where(r => r.Create.Depth > 0 || r.Write.Depth > 0 || r.Delete.Depth > 0 || r.Assign.Depth > 0)
            .ToList();
        if (sensitive.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.High,
                Title = $"Có quyền ghi trên {sensitive.Count} entity nhạy cảm về bảo mật/cấu hình",
                Detail = Names(sensitive.Select(r => $"{r.DisplayName} ({r.LogicalName})")),
            };
        }

        foreach (var misc in miscPrivileges.Where(m => m.IsGranted && SensitiveMiscPrivileges.ContainsKey(m.Name)))
        {
            yield return new AnalysisFinding
            {
                Severity = misc.Name.StartsWith("prvBypass", StringComparison.OrdinalIgnoreCase)
                           || misc.Name.StartsWith("prvDelete", StringComparison.OrdinalIgnoreCase)
                           || misc.Name.Equals("prvActOnBehalfOfAnotherUser", StringComparison.OrdinalIgnoreCase)
                    ? FindingSeverity.High
                    : FindingSeverity.Medium,
                Title = $"Privilege nhạy cảm: {misc.Name}",
                Detail = $"{SensitiveMiscPrivileges[misc.Name]} – mức {misc.Depth.ToText()}",
            };
        }

        var orgDelete = granted.Where(r => r.Delete.Depth == PrivilegeDepth.Organization).ToList();
        if (orgDelete.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = orgDelete.Count > 20 ? FindingSeverity.High : FindingSeverity.Medium,
                Title = $"Delete mức Organization trên {orgDelete.Count} entity",
                Detail = Names(orgDelete.Select(r => r.DisplayName)),
            };
        }

        var orgWrite = granted.Count(r => r.Write.Depth == PrivilegeDepth.Organization);
        if (orgWrite > 50)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Medium,
                Title = $"Write mức Organization trên {orgWrite} entity",
                Detail = "Role có phạm vi ghi rất rộng – cân nhắc giới hạn theo Business Unit hoặc User.",
            };
        }

        var orgAssignShare = granted.Count(r => r.Assign.Depth == PrivilegeDepth.Organization || r.Share.Depth == PrivilegeDepth.Organization);
        if (orgAssignShare > 30)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Low,
                Title = $"Assign/Share mức Organization trên {orgAssignShare} entity",
                Detail = "User có thể chuyển quyền sở hữu hoặc chia sẻ dữ liệu của toàn tổ chức.",
            };
        }
    }

    public static IEnumerable<AnalysisFinding> BuildFindings(RoleAnalysis analysis)
    {
        foreach (var finding in BuildPrivilegeFindings(analysis.EntityRows, analysis.MiscPrivileges))
            yield return finding;

        var disabled = analysis.Users.Where(u => u.IsDisabled).ToList();
        if (disabled.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Low,
                Title = $"{disabled.Count} user đã disabled vẫn còn được gán role",
                Detail = Names(disabled.Select(u => u.FullName)),
            };
        }

        var redundant = analysis.Users.Where(u => u.AlsoViaTeam).ToList();
        if (redundant.Count > 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = $"{redundant.Count} user nhận role vừa trực tiếp vừa qua team",
                Detail = "Có thể gỡ gán trực tiếp để quản lý tập trung qua team: " + Names(redundant.Select(u => u.FullName)),
            };
        }

        if (analysis.Users.Count == 0 && analysis.Teams.Count == 0)
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "Role chưa được gán cho user hoặc team nào",
                Detail = "Có thể là role không còn sử dụng – cân nhắc dọn dẹp.",
            };
        }

        if (!analysis.Components.Any(c => c.Category == ComponentCategory.App))
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "Role không được thêm vào Model-driven App nào",
                Detail = "User chỉ có role này sẽ không mở được app nào (trừ khi có role khác được gán vào app).",
            };
        }

        if (!analysis.EntityRows.Any(r => r.HasAnyPrivilege))
        {
            yield return new AnalysisFinding
            {
                Severity = FindingSeverity.Info,
                Title = "Role không có privilege nào trên entity",
                Detail = "Thường dùng làm role bổ sung (ví dụ chỉ để mở app hoặc form).",
            };
        }
    }

    internal static async Task<T> TryAsync<T>(Func<Task<T>> action, T fallback, string what, List<string> warnings)
    {
        try
        {
            return await action();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            warnings.Add($"Không tải được {what}: {ex.Message}");
            return fallback;
        }
    }

    private static string FormTypeText(int type) => type switch
    {
        0 => "Dashboard",
        2 => "Main",
        6 => "Quick View",
        7 => "Quick Create",
        10 => "Interactive Dashboard",
        12 => "Main - Interactive",
        103 => "Power BI Dashboard",
        _ => type.ToString(),
    };

    private static string ViewTypeText(int type) => type switch
    {
        0 => "Public",
        1 => "Advanced Find",
        2 => "Associated",
        4 => "Quick Find",
        64 => "Lookup",
        _ => type.ToString(),
    };
}
