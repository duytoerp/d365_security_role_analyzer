using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Áp kết quả so sánh snapshot vào môi trường đang kết nối: đưa privilege của role về đúng như bản B.
/// Role và privilege được khớp theo tên vì Id khác nhau giữa các môi trường.
/// </summary>
public static class SnapshotApplyService
{
    /// <summary>
    /// Áp các dòng diff đã chọn. <paramref name="source"/> là snapshot B (bản muốn đạt tới).
    /// Chỉ áp dòng privilege và dòng role thêm mới; các loại khác được bỏ qua và liệt kê lại.
    /// </summary>
    public static async Task<SnapshotApplyResult> ApplyAsync(
        DataverseService service,
        EnvironmentSnapshot source,
        IReadOnlyCollection<SnapshotDiffRow> rows,
        IProgress<(string Text, double Percent)>? progress = null,
        CancellationToken ct = default)
    {
        var result = new SnapshotApplyResult();
        var catalog = await service.GetPrivilegeCatalogAsync(ct);
        var privilegesByName = catalog
            .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var roles = await service.GetRolesAsync(ct);
        var rolesByName = roles
            .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var sourceRoles = source.Roles
            .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var row in rows.Where(r => !r.CanApply))
            result.Skipped.Add($"{row.Category}: {row.Item} – {row.Detail}");

        var byRole = rows
            .Where(r => r.CanApply)
            .GroupBy(r => r.Item, StringComparer.OrdinalIgnoreCase)
            .ToList();

        BusinessUnitInfo? rootBusinessUnit = null;
        var done = 0;

        foreach (var group in byRole)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report(($"Đang áp role {done + 1}/{byRole.Count}: {group.Key}", done * 100.0 / byRole.Count));
            done++;

            if (!sourceRoles.TryGetValue(group.Key, out var sourceRole))
            {
                result.Skipped.Add($"Role \"{group.Key}\" không có trong snapshot nguồn.");
                continue;
            }

            try
            {
                var created = false;
                if (!rolesByName.TryGetValue(group.Key, out var target))
                {
                    // Role chưa tồn tại: tạo trong BU gốc rồi gán toàn bộ privilege của bản B.
                    rootBusinessUnit ??= (await service.GetBusinessUnitsAsync(ct)).FirstOrDefault(b => b.ParentId is null);
                    if (rootBusinessUnit is not { } bu)
                    {
                        result.Errors.Add($"{group.Key}: không xác định được Business Unit gốc để tạo role.");
                        continue;
                    }

                    var newId = await service.CreateRoleAsync(group.Key, bu.Id, bu.Name, inherited: true, ct);
                    target = new SecurityRoleInfo { Id = newId, Name = group.Key, BusinessUnitId = bu.Id, BusinessUnitName = bu.Name };
                    rolesByName[group.Key] = target;
                    created = true;
                    result.RolesCreated++;
                }

                var changes = BuildChanges(group.ToList(), sourceRole, privilegesByName, created, result);
                if (changes.Count == 0)
                    continue;

                await service.UpdateRolePrivilegesAsync(target.Id, target.Name, changes, "Áp diff snapshot", ct);
                result.RolesUpdated++;
                result.PrivilegesApplied += changes.Count;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                result.Errors.Add($"{group.Key}: {ex.Message}");
            }
        }

        return result;
    }

    private static List<(PrivilegeDefinition Privilege, PrivilegeDepth Depth)> BuildChanges(
        List<SnapshotDiffRow> rows, SnapshotRole sourceRole,
        Dictionary<string, PrivilegeDefinition> privilegesByName, bool wholeRole, SnapshotApplyResult result)
    {
        var changes = new List<(PrivilegeDefinition, PrivilegeDepth)>();

        // Dòng "role thêm mới" đại diện cho cả role: lấy toàn bộ privilege từ snapshot.
        var wanted = wholeRole || rows.Any(r => r.Category == SnapshotService.CategoryRole)
            ? sourceRole.Privileges.Select(p => (Name: p.Key, Depth: p.Value)).ToList()
            : rows.Where(r => r.Category == SnapshotService.CategoryPrivilege)
                  .Select(r => (Name: r.Detail, Depth: r.TargetDepth))
                  .ToList();

        foreach (var (name, depth) in wanted)
        {
            if (!privilegesByName.TryGetValue(name, out var definition))
            {
                result.Skipped.Add($"Privilege \"{name}\" không có trên môi trường này ({sourceRole.Name}).");
                continue;
            }
            changes.Add((definition, definition.Clamp(depth)));
        }
        return changes;
    }
}
