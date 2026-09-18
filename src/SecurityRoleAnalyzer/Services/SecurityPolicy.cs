using System.IO;
using System.Text.Json;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Bộ quy tắc rà soát: entity nhạy cảm, privilege nhạy cảm và các ngưỡng cảnh báo.
/// Mặc định dùng bộ dựng sẵn; mỗi tổ chức có thể thay bằng file policy.json trong thư mục dữ liệu.
/// </summary>
public sealed class SecurityPolicy
{
    /// <summary>Entity mà quyền ghi lên đó ảnh hưởng tới chính cấu hình bảo mật của môi trường.</summary>
    public List<string> SensitiveEntities { get; set; } =
    [
        "role", "systemuser", "team", "businessunit", "fieldsecurityprofile", "fieldpermission",
        "pluginassembly", "plugintype", "sdkmessageprocessingstep", "sdkmessageprocessingstepimage",
        "solution", "workflow", "customapi", "environmentvariablevalue", "connectionreference",
        "organization", "audit", "position", "hierarchysecurityconfiguration",
    ];

    /// <summary>Privilege nhạy cảm → mô tả hiển thị trong phần phát hiện.</summary>
    public Dictionary<string, string> SensitivePrivileges { get; set; } = new(StringComparer.OrdinalIgnoreCase)
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

    /// <summary>Privilege coi là mức Cao (còn lại là Trung bình).</summary>
    public List<string> HighSeverityPrefixes { get; set; } = ["prvBypass", "prvDelete"];

    public List<string> HighSeverityPrivileges { get; set; } = ["prvActOnBehalfOfAnotherUser"];

    /// <summary>Số entity có Delete mức Organization vượt ngưỡng này thì nâng lên mức Cao.</summary>
    public int OrgDeleteHighThreshold { get; set; } = 20;

    /// <summary>Số entity có Write mức Organization vượt ngưỡng này thì cảnh báo.</summary>
    public int OrgWriteThreshold { get; set; } = 50;

    /// <summary>Số entity có Assign/Share mức Organization vượt ngưỡng này thì cảnh báo.</summary>
    public int OrgAssignShareThreshold { get; set; } = 30;

    /// <summary>Hai role trùng nhau từ tỉ lệ này trở lên thì coi là ứng viên gộp (0–1).</summary>
    public double DuplicateRoleSimilarity { get; set; } = 0.9;

    public bool IsSensitiveEntity(string logicalName) =>
        SensitiveEntities.Contains(logicalName, StringComparer.OrdinalIgnoreCase);

    public FindingSeverity SeverityOf(string privilegeName) =>
        HighSeverityPrivileges.Contains(privilegeName, StringComparer.OrdinalIgnoreCase)
        || HighSeverityPrefixes.Any(p => privilegeName.StartsWith(p, StringComparison.OrdinalIgnoreCase))
            ? FindingSeverity.High
            : FindingSeverity.Medium;

    #region Nạp / lưu

    public static string FilePath => Path.Combine(ConnectionProfileStore.AppDataFolder, "policy.json");

    /// <summary>Bộ quy tắc đang dùng; nạp lại bằng <see cref="Reload"/>.</summary>
    public static SecurityPolicy Current { get; private set; } = Load();

    /// <summary>Có đang dùng file policy.json của người dùng hay không.</summary>
    public static bool IsCustom { get; private set; }

    public static SecurityPolicy Load()
    {
        try
        {
            if (File.Exists(FilePath)
                && JsonSerializer.Deserialize<SecurityPolicy>(File.ReadAllText(FilePath), JsonDefaults.Options) is { } policy)
            {
                IsCustom = true;
                return Normalize(policy);
            }
        }
        catch (Exception ex)
        {
            ErrorLog.Write("Đọc policy.json", ex);
        }

        IsCustom = false;
        return new SecurityPolicy();
    }

    public static SecurityPolicy Reload() => Current = Load();

    /// <summary>Ghi bộ quy tắc hiện tại ra file để người dùng chỉnh sửa.</summary>
    public static string SaveTemplate()
    {
        Directory.CreateDirectory(ConnectionProfileStore.AppDataFolder);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(Current, JsonDefaults.Options));
        return FilePath;
    }

    /// <summary>Dictionary nạp từ JSON không giữ comparer, nên phải dựng lại để so sánh không phân biệt hoa thường.</summary>
    private static SecurityPolicy Normalize(SecurityPolicy policy)
    {
        policy.SensitivePrivileges = new Dictionary<string, string>(policy.SensitivePrivileges, StringComparer.OrdinalIgnoreCase);
        return policy;
    }

    #endregion
}
