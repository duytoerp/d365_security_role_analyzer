namespace SecurityRoleAnalyzer.Models;

/// <summary>Chủ sở hữu và Business Unit của một bản ghi cụ thể.</summary>
public sealed class RecordOwnerInfo
{
    public string EntityLogicalName { get; init; } = "";
    public string EntityDisplayName { get; init; } = "";
    public Guid RecordId { get; init; }
    public string RecordName { get; init; } = "";
    public Guid OwnerId { get; init; }
    public string OwnerName { get; init; } = "";
    public bool OwnerIsTeam { get; init; }
    public Guid OwningBusinessUnitId { get; init; }
    public string OwningBusinessUnitName { get; init; } = "";
    /// <summary>Bảng thuộc sở hữu tổ chức: quyền không phụ thuộc owner, chỉ có mức Organization.</summary>
    public bool IsOrganizationOwned { get; init; }

    public string Caption => string.IsNullOrEmpty(RecordName)
        ? $"{EntityDisplayName} · {RecordId}"
        : $"{EntityDisplayName}: {RecordName}";

    public string OwnerText => IsOrganizationOwned
        ? "Bản ghi thuộc sở hữu tổ chức (không có owner)"
        : $"{(OwnerIsTeam ? "Team" : "User")}: {OwnerName}"
          + (string.IsNullOrEmpty(OwningBusinessUnitName) ? "" : $" · Business Unit: {OwningBusinessUnitName}");
}

/// <summary>Một principal được chia sẻ bản ghi.</summary>
public sealed class RecordShareRow
{
    public Guid PrincipalId { get; init; }
    /// <summary>"systemuser" hoặc "team".</summary>
    public string PrincipalType { get; init; } = "";
    public string PrincipalName { get; init; } = "";
    public AccessRight[] Rights { get; init; } = [];

    public bool IsTeam => PrincipalType == "team";
    public string TypeText => IsTeam ? "Team" : "User";
    public string RightsText => Rights.Length == 0 ? "(không có quyền)" : string.Join(", ", Rights);
}

/// <summary>
/// Mẫu access team: Dataverse tự tạo team truy cập cho từng bản ghi theo mẫu này.
/// Quyền cấp qua đây không nằm trong security role nên phân tích theo role không thấy được.
/// </summary>
public sealed class AccessTeamTemplateInfo
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public int EntityTypeCode { get; init; }
    public string EntityLogicalName { get; set; } = "";
    public string EntityDisplayName { get; set; } = "";
    public int AccessRightsMask { get; init; }
    public string Description { get; init; } = "";

    public string EntityText => string.IsNullOrEmpty(EntityDisplayName)
        ? $"(mã bảng {EntityTypeCode})"
        : $"{EntityDisplayName} ({EntityLogicalName})";

    public string RightsText => AccessRightsText(AccessRightsMask);

    /// <summary>Giải mã mặt nạ quyền của Dataverse (cùng bảng giá trị với AccessRights của SDK).</summary>
    public static string AccessRightsText(int mask)
    {
        var names = new List<string>();
        if ((mask & 1) != 0) names.Add("Read");
        if ((mask & 2) != 0) names.Add("Write");
        if ((mask & 4) != 0) names.Add("Append");
        if ((mask & 16) != 0) names.Add("AppendTo");
        if ((mask & 32) != 0) names.Add("Create");
        if ((mask & 65536) != 0) names.Add("Delete");
        if ((mask & 262144) != 0) names.Add("Share");
        if ((mask & 524288) != 0) names.Add("Assign");
        return names.Count == 0 ? "(không có quyền)" : string.Join(", ", names);
    }
}

/// <summary>Cấu hình hierarchy security của môi trường.</summary>
public sealed class HierarchySecurityInfo
{
    public bool IsEnabled { get; init; }
    /// <summary>true = position hierarchy tùy chỉnh, false = theo manager.</summary>
    public bool UsesPositions { get; init; }
    public int Depth { get; init; }
    /// <summary>Đọc được cấu hình hay không (bảng không có ở mọi phiên bản).</summary>
    public bool IsReadable { get; init; } = true;

    public string Text => !IsReadable
        ? "Không đọc được cấu hình hierarchy security trên môi trường này."
        : !IsEnabled
            ? "Hierarchy security đang tắt."
            : $"Hierarchy security đang bật theo {(UsesPositions ? "position hierarchy" : "manager hierarchy")}, "
              + $"sâu {Depth} cấp: cấp trên đọc/ghi được dữ liệu của cấp dưới.";
}

/// <summary>Một lý do giải thích vì sao user có (hoặc không có) quyền trên bản ghi.</summary>
public sealed class AccessReason
{
    public string Source { get; init; } = "";
    public string Detail { get; init; } = "";
    public bool Grants { get; init; }

    public string Icon => Grants ? "✔" : "—";
}

/// <summary>Kết quả trả lời câu hỏi "vì sao user X không thấy bản ghi Y?".</summary>
public sealed class RecordAccessExplanation
{
    public required UserInfo User { get; init; }
    public required RecordOwnerInfo Record { get; init; }
    /// <summary>Quyền thực tế Dataverse trả về (nguồn sự thật).</summary>
    public AccessRight[] EffectiveRights { get; init; } = [];
    public List<AccessReason> Reasons { get; init; } = [];
    public List<RecordShareRow> Shares { get; init; } = [];
    public List<string> Warnings { get; init; } = [];

    public bool CanRead => EffectiveRights.Contains(AccessRight.Read);

    public string Headline => CanRead
        ? $"{User.FullName} ĐỌC ĐƯỢC bản ghi này."
        : $"{User.FullName} KHÔNG đọc được bản ghi này.";

    public string RightsText => EffectiveRights.Length == 0
        ? "Không có quyền nào trên bản ghi này."
        : "Quyền hiệu lực: " + string.Join(", ", EffectiveRights);
}
