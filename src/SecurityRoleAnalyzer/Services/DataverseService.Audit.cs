using Microsoft.Xrm.Sdk;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Đọc audit log của Dataverse để biết ai thay đổi phân quyền, kể cả thay đổi không thực hiện
/// từ ứng dụng này. Yêu cầu môi trường đã bật Auditing cho các bảng tương ứng.
/// </summary>
public sealed partial class DataverseService
{
    /// <summary>action của bảng audit liên quan tới phân quyền.</summary>
    private static readonly Dictionary<int, string> AuditActions = new()
    {
        [1] = "Tạo",
        [2] = "Cập nhật",
        [3] = "Xóa",
        [4] = "Kích hoạt",
        [11] = "Gán role cho user",
        [12] = "Gỡ role của user",
        [13] = "Gán role cho team",
        [14] = "Gỡ role của team",
        [15] = "Thêm thành viên team",
        [16] = "Gỡ thành viên team",
        [33] = "Thêm thành viên",
        [34] = "Gỡ thành viên",
        [43] = "Gán role",
        [44] = "Gỡ role",
    };

    /// <summary>
    /// Các thay đổi phân quyền trong <paramref name="days"/> ngày gần nhất.
    /// Trả về danh sách rỗng nếu môi trường chưa bật auditing.
    /// </summary>
    public async Task<List<AuditEntry>> GetSecurityAuditAsync(int days = 30, int max = 2000, CancellationToken ct = default)
    {
        var from = DateTime.UtcNow.AddDays(-days).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var fetch = $"""
            <fetch top="{max}">
              <entity name="audit">
                <attribute name="auditid" />
                <attribute name="createdon" />
                <attribute name="action" />
                <attribute name="operation" />
                <attribute name="objecttypecode" />
                <attribute name="objectid" />
                <attribute name="userid" />
                <attribute name="attributemask" />
                <order attribute="createdon" descending="true" />
                <filter>
                  <condition attribute="createdon" operator="on-or-after" value="{from}" />
                  <condition attribute="objecttypecode" operator="in">
                    <value>role</value><value>systemuser</value><value>team</value>
                    <value>fieldsecurityprofile</value><value>businessunit</value>
                  </condition>
                </filter>
              </entity>
            </fetch>
            """;

        var entities = await FetchAllAsync(fetch, ct);
        return entities.Select(e => new AuditEntry
        {
            Id = e.Id,
            CreatedOn = e.GetAttributeValue<DateTime>("createdon").ToLocalTime(),
            Action = ActionText(e.GetAttributeValue<OptionSetValue>("action")?.Value ?? 0),
            EntityName = e.GetAttributeValue<string>("objecttypecode") ?? "",
            TargetName = e.GetAttributeValue<EntityReference>("objectid")?.Name ?? "",
            TargetId = e.GetAttributeValue<EntityReference>("objectid")?.Id ?? Guid.Empty,
            UserName = e.GetAttributeValue<EntityReference>("userid")?.Name ?? "",
        }).ToList();
    }

    private static string ActionText(int action) =>
        AuditActions.TryGetValue(action, out var text) ? text : $"Mã {action}";

    /// <summary>Môi trường có bật auditing ở cấp tổ chức hay không.</summary>
    public async Task<bool> IsAuditEnabledAsync(CancellationToken ct = default)
    {
        const string fetch = """
            <fetch top="1">
              <entity name="organization">
                <attribute name="isauditenabled" />
              </entity>
            </fetch>
            """;
        var entities = await FetchAllAsync(fetch, ct);
        return entities.FirstOrDefault()?.GetAttributeValue<bool>("isauditenabled") ?? false;
    }
}
