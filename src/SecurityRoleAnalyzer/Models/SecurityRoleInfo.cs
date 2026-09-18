namespace SecurityRoleAnalyzer.Models;

public sealed class SecurityRoleInfo
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public Guid BusinessUnitId { get; init; }
    public string BusinessUnitName { get; init; } = "";
    public bool IsManaged { get; init; }
    public DateTime? ModifiedOn { get; init; }

    /// <summary>
    /// Member's privilege inheritance. false = "Team privileges only": thành viên team chỉ dùng được
    /// quyền này trên record do team sở hữu, không nhận quyền mức User cho chính mình.
    /// </summary>
    public bool IsInherited { get; init; } = true;

    /// <summary>Id template của role hệ thống (không đổi theo ngôn ngữ), null với role tự tạo.</summary>
    public Guid? RoleTemplateId { get; init; }

    /// <summary>Role System Administrator, nhận diện theo template nên không phụ thuộc ngôn ngữ.</summary>
    public bool IsSystemAdministrator =>
        RoleTemplateId == RoleTemplates.SystemAdministrator || RoleTemplates.IsAdminName(Name);

    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";

    public string InheritanceText => IsInherited ? "User + Team" : "Chỉ quyền Team";

    public override string ToString() => Name;
}

/// <summary>Id template cố định của các role hệ thống Dataverse (không đổi giữa các môi trường/ngôn ngữ).</summary>
public static class RoleTemplates
{
    public static readonly Guid SystemAdministrator = new("627090ff-40a3-4053-8790-584edc5be201");
    public static readonly Guid SystemCustomizer = new("119f245c-3cc8-4b62-b31c-d1a046ced15d");

    private static readonly string[] AdminNames =
    [
        "System Administrator", "Quản trị viên hệ thống", "Systemadministrator", "Administrateur système",
    ];

    /// <summary>Dự phòng khi role không có template (ví dụ bản sao thủ công).</summary>
    public static bool IsAdminName(string name) =>
        AdminNames.Contains(name.Trim(), StringComparer.OrdinalIgnoreCase);
}

/// <summary>Bản sao của role trong từng Business Unit (Dataverse tự tạo cho mỗi BU).</summary>
public sealed record RoleCopy(Guid RoleId, Guid BusinessUnitId, string BusinessUnitName);

public sealed class EntityInfo
{
    public string LogicalName { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public bool IsCustom { get; init; }
    public bool IsIntersect { get; init; }
    public bool IsBpfEntity { get; init; }
}
