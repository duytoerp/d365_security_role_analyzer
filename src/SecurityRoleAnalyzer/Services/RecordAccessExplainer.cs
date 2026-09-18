using System.Text.RegularExpressions;
using Microsoft.Xrm.Sdk;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Trả lời câu hỏi "vì sao user X không thấy/không sửa được bản ghi Y?".
/// Quyền hiệu lực lấy trực tiếp từ Dataverse (RetrievePrincipalAccess) nên luôn đúng;
/// phần lý do ghép thêm từ role, chủ sở hữu, chia sẻ và hierarchy security.
/// </summary>
public static partial class RecordAccessExplainer
{
    public static async Task<RecordAccessExplanation> ExplainAsync(
        DataverseService service, UserInfo user, string entityLogicalName, Guid recordId,
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var warnings = new List<string>();

        progress?.Report("Đang đọc thông tin bản ghi...");
        var record = await service.GetRecordOwnerAsync(entityLogicalName, recordId, ct)
                     ?? throw new InvalidOperationException("Không đọc được bản ghi.");

        progress?.Report("Đang hỏi Dataverse quyền hiệu lực...");
        var rights = await service.GetPrincipalAccessAsync(new EntityReference(entityLogicalName, recordId), user.Id, ct);

        var shares = await RoleAnalyzer.TryAsync(
            () => service.GetRecordSharesAsync(new EntityReference(entityLogicalName, recordId), ct), [], "chia sẻ bản ghi", warnings);

        progress?.Report("Đang xác định nguồn quyền...");
        var reasons = await BuildReasonsAsync(service, user, record, rights, shares, warnings, ct);

        return new RecordAccessExplanation
        {
            User = user,
            Record = record,
            EffectiveRights = rights,
            Reasons = reasons,
            Shares = shares,
            Warnings = warnings,
        };
    }

    private static async Task<List<AccessReason>> BuildReasonsAsync(
        DataverseService service, UserInfo user, RecordOwnerInfo record, AccessRight[] rights,
        List<RecordShareRow> shares, List<string> warnings, CancellationToken ct)
    {
        var reasons = new List<AccessReason>();

        // 1. Chủ sở hữu.
        if (record.IsOrganizationOwned)
        {
            reasons.Add(new AccessReason
            {
                Source = "Loại bảng",
                Detail = "Bảng thuộc sở hữu tổ chức – quyền chỉ có mức Organization, không phụ thuộc chủ sở hữu.",
                Grants = false,
            });
        }
        else if (record.OwnerId == user.Id)
        {
            reasons.Add(new AccessReason
            {
                Source = "Chủ sở hữu",
                Detail = "User chính là chủ sở hữu bản ghi, nên quyền mức User (Basic) đã đủ.",
                Grants = true,
            });
        }
        else
        {
            var sameBu = record.OwningBusinessUnitId == user.BusinessUnitId;
            reasons.Add(new AccessReason
            {
                Source = "Chủ sở hữu",
                Detail = $"Bản ghi thuộc về {(record.OwnerIsTeam ? "team" : "user")} \"{record.OwnerName}\""
                         + $" (Business Unit \"{record.OwningBusinessUnitName}\"). "
                         + (sameBu
                             ? "Cùng Business Unit với user, nên quyền mức Business Unit là đủ."
                             : "Khác Business Unit của user, nên cần quyền mức Parent:Child hoặc Organization."),
                Grants = false,
            });
        }

        // 2. Role của user trên bảng này.
        await AddRoleReasonsAsync(service, user, record, reasons, warnings, ct);

        // 3. Chia sẻ bản ghi.
        var direct = shares.FirstOrDefault(s => !s.IsTeam && s.PrincipalId == user.Id);
        if (direct is not null)
        {
            reasons.Add(new AccessReason
            {
                Source = "Chia sẻ bản ghi",
                Detail = $"Bản ghi được chia sẻ trực tiếp cho user với quyền: {direct.RightsText}.",
                Grants = true,
            });
        }
        else if (shares.Count > 0)
        {
            reasons.Add(new AccessReason
            {
                Source = "Chia sẻ bản ghi",
                Detail = $"Bản ghi được chia sẻ cho {shares.Count} principal khác (xem tab Chia sẻ); "
                         + "user có thể nhận quyền nếu thuộc một trong các team đó.",
                Grants = false,
            });
        }

        // 4. Hierarchy security.
        await AddHierarchyReasonAsync(service, user, record, reasons, warnings, ct);

        // 5. Kết luận theo quyền thực tế.
        reasons.Add(new AccessReason
        {
            Source = "Kết luận",
            Detail = rights.Length == 0
                ? "Dataverse không cấp quyền nào cho user trên bản ghi này."
                : "Quyền Dataverse thực sự cấp: " + string.Join(", ", rights),
            Grants = rights.Length > 0,
        });

        return reasons;
    }

    private static async Task AddRoleReasonsAsync(
        DataverseService service, UserInfo user, RecordOwnerInfo record,
        List<AccessReason> reasons, List<string> warnings, CancellationToken ct)
    {
        try
        {
            var catalog = await service.GetPrivilegeCatalogAsync(ct);
            var readPrivileges = catalog
                .Where(p => string.Equals(p.EntityLogicalName, record.EntityLogicalName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (readPrivileges.Count == 0)
            {
                reasons.Add(new AccessReason
                {
                    Source = "Security role",
                    Detail = $"Không tìm thấy privilege nào cho bảng \"{record.EntityLogicalName}\" trong danh mục.",
                    Grants = false,
                });
                return;
            }

            var direct = await service.GetUserDirectRolesAsync(user.Id, ct);
            var teams = await service.GetUserTeamsAsync(user.Id, ct);
            var viaTeams = await service.GetRolesOfTeamsAsync(teams, ct);
            var all = direct.Concat(viaTeams).DistinctBy(r => (r.RootRoleId, r.TeamId)).ToList();

            var byRight = new Dictionary<AccessRight, (PrivilegeDepth Depth, string Source)>();
            foreach (var role in all.DistinctBy(r => r.RootRoleId))
            {
                var privileges = await service.GetRolePrivilegesAsync(role.RootRoleId, ct);
                foreach (var definition in readPrivileges)
                {
                    var depth = privileges.GetValueOrDefault(definition.Id);
                    if (depth == PrivilegeDepth.None)
                        continue;
                    if (!byRight.TryGetValue(definition.AccessRight, out var best) || best.Depth < depth)
                        byRight[definition.AccessRight] = (depth, UserAnalyzer.SourceLabel(role));
                }
            }

            if (byRight.Count == 0)
            {
                reasons.Add(new AccessReason
                {
                    Source = "Security role",
                    Detail = $"Không role nào của user có quyền trên bảng \"{record.EntityDisplayName}\".",
                    Grants = false,
                });
                return;
            }

            foreach (var (right, value) in byRight.OrderBy(x => x.Key))
            {
                reasons.Add(new AccessReason
                {
                    Source = $"Role – {right}",
                    Detail = $"Mức {value.Depth.ToText()} từ \"{value.Source}\".",
                    Grants = true,
                });
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            warnings.Add("Không đọc được role của user: " + ex.Message);
        }
    }

    private static async Task AddHierarchyReasonAsync(
        DataverseService service, UserInfo user, RecordOwnerInfo record,
        List<AccessReason> reasons, List<string> warnings, CancellationToken ct)
    {
        try
        {
            var hierarchy = await service.GetHierarchySecurityAsync(ct);
            if (!hierarchy.IsEnabled)
                return;

            var grants = false;
            var detail = hierarchy.Text;

            if (!hierarchy.UsesPositions && record.OwnerId != Guid.Empty && !record.OwnerIsTeam)
            {
                // User là cấp trên của chủ sở hữu thì nhận quyền qua manager hierarchy.
                var chain = await service.GetManagerChainAsync(record.OwnerId, hierarchy.Depth <= 0 ? 10 : hierarchy.Depth, ct);
                if (chain.Any(m => m.Id == user.Id))
                {
                    grants = true;
                    detail += $" User là cấp trên của \"{record.OwnerName}\" trong chuỗi quản lý.";
                }
            }

            reasons.Add(new AccessReason { Source = "Hierarchy security", Detail = detail, Grants = grants });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            warnings.Add("Không đọc được hierarchy security: " + ex.Message);
        }
    }

    /// <summary>
    /// Tách entity và Id từ URL bản ghi của D365, ví dụ
    /// <c>https://org.crm5.dynamics.com/main.aspx?pagetype=entityrecord&amp;etn=account&amp;id=...</c>.
    /// Cũng chấp nhận dạng "account/00000000-0000-0000-0000-000000000000" hoặc "account 000...".
    /// </summary>
    public static (string Entity, Guid Id)? ParseRecordReference(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        var trimmed = text.Trim();

        var etn = EtnPattern().Match(trimmed);
        var id = IdPattern().Match(trimmed);
        if (etn.Success && id.Success && Guid.TryParse(id.Groups[1].Value, out var urlId))
            return (etn.Groups[1].Value, urlId);

        var plain = PlainPattern().Match(trimmed);
        if (plain.Success && Guid.TryParse(plain.Groups[2].Value, out var plainId))
            return (plain.Groups[1].Value, plainId);

        return null;
    }

    [GeneratedRegex(@"[?&]etn=([a-zA-Z0-9_]+)", RegexOptions.IgnoreCase)]
    private static partial Regex EtnPattern();

    [GeneratedRegex(@"[?&]id=%?7?B?([0-9a-fA-F-]{36})", RegexOptions.IgnoreCase)]
    private static partial Regex IdPattern();

    [GeneratedRegex(@"^([a-zA-Z0-9_]+)[\s/,;:]+\{?([0-9a-fA-F-]{36})\}?$")]
    private static partial Regex PlainPattern();
}
