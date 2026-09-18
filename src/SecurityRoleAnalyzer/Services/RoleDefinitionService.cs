using System.IO;
using System.Text.Json;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Xuất/nhập định nghĩa đầy đủ của một role (privilege + app) dưới dạng JSON, để mang role
/// từ môi trường này sang môi trường khác. Privilege và app được khớp theo tên/unique name
/// vì Id khác nhau giữa các môi trường.
/// </summary>
public static class RoleDefinitionService
{
    public static async Task<RoleDefinition> ExportAsync(DataverseService service, SecurityRoleInfo role, CancellationToken ct = default)
    {
        var catalog = await service.GetPrivilegeCatalogAsync(ct);
        var names = catalog.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First().Name);
        var privileges = await service.GetRolePrivilegesAsync(role.Id, ct);

        var copies = await service.GetRoleCopiesAsync(role, ct);
        var apps = await service.GetAppsForRoleAsync(copies.Select(c => c.RoleId).Append(role.Id).ToHashSet(), ct);

        return new RoleDefinition
        {
            Name = role.Name,
            SourceEnvironment = service.EnvironmentKey,
            SourceRoleId = role.Id,
            BusinessUnitName = role.BusinessUnitName,
            IsInherited = role.IsInherited,
            Privileges = privileges
                .Where(p => p.Value > PrivilegeDepth.None)
                .Select(p => new PrivilegeBackupItem
                {
                    PrivilegeId = p.Key,
                    Name = names.GetValueOrDefault(p.Key, p.Key.ToString()),
                    Depth = p.Value,
                })
                .OrderBy(p => p.Name)
                .ToList(),
            Apps = apps.Select(a => a.UniqueName).Where(n => !string.IsNullOrEmpty(n)).OrderBy(n => n).ToList(),
        };
    }

    public static void Save(RoleDefinition definition, string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(definition, JsonDefaults.Options));

    public static RoleDefinition Load(string path) =>
        JsonSerializer.Deserialize<RoleDefinition>(File.ReadAllText(path), JsonDefaults.Options)
        ?? throw new InvalidDataException("File định nghĩa role không hợp lệ.");

    /// <summary>
    /// Áp định nghĩa vào môi trường đang kết nối. <paramref name="targetRoleId"/> null thì tạo role mới
    /// trong <paramref name="businessUnitId"/>; ngược lại thay toàn bộ privilege của role đó.
    /// </summary>
    public static async Task<RoleImportResult> ApplyAsync(
        DataverseService service, RoleDefinition definition, Guid? targetRoleId,
        Guid businessUnitId, string businessUnitName, bool linkApps, CancellationToken ct = default)
    {
        var result = new RoleImportResult();
        var catalog = await service.GetPrivilegeCatalogAsync(ct);
        var byName = catalog
            .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        if (targetRoleId is { } existing)
        {
            result.RoleId = existing;
        }
        else
        {
            result.RoleId = await service.CreateRoleAsync(definition.Name, businessUnitId, businessUnitName, definition.IsInherited, ct);
            result.Created = true;
        }

        // Khớp theo tên privilege; Id trong file là của môi trường nguồn nên không dùng được.
        var backup = new PrivilegeBackup
        {
            Environment = definition.SourceEnvironment,
            RoleName = definition.Name,
            CreatedOn = definition.ExportedOn,
            Privileges = definition.Privileges,
        };
        result.MissingPrivileges = await service.RestorePrivilegeBackupAsync(backup, result.RoleId, definition.Name, null, ct);
        result.PrivilegesApplied = definition.GrantedCount - result.MissingPrivileges.Count;

        if (linkApps && definition.Apps.Count > 0)
            await LinkAppsAsync(service, definition, result, ct);

        return result;
    }

    private static async Task LinkAppsAsync(DataverseService service, RoleDefinition definition, RoleImportResult result, CancellationToken ct)
    {
        var apps = await service.GetAppModulesAsync(ct);
        var byUniqueName = apps
            .GroupBy(a => a.UniqueName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var uniqueName in definition.Apps)
        {
            if (!byUniqueName.TryGetValue(uniqueName, out var app))
            {
                result.MissingApps.Add(uniqueName);
                continue;
            }

            try
            {
                await service.AssociateAppRolesAsync(app.Id, app.Name, [(result.RoleId, definition.Name)], null, ct);
                result.AppsLinked++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Role đã có sẵn trong app thì Dataverse báo lỗi trùng – không coi là hỏng.
                ErrorLog.Write($"Thêm role \"{definition.Name}\" vào app \"{app.Name}\"", ex);
            }
        }
    }
}
