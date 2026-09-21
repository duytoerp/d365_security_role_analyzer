namespace SecurityRoleAnalyzer.Models;

/// <summary>Cách một form/dashboard được mở cho người dùng (tương ứng màn hình Form settings → Security roles).</summary>
public enum FormVisibility
{
    /// <summary>Loại form không gán được security role (Quick View, Quick Create) – đi theo quyền Read entity.</summary>
    NotRoleScoped,

    /// <summary>Tùy chọn "Everyone": mọi role đều thấy form.</summary>
    Everyone,

    /// <summary>Tùy chọn "Specific security roles": chỉ các role được liệt kê.</summary>
    SpecificRoles,

    /// <summary>displayconditions hỏng – không đọc được danh sách role, không được coi là Everyone.</summary>
    Unreadable,
}

/// <summary>Một security role được gán cho form. Id luôn đã quy về role gốc.</summary>
public sealed record FormRoleAssignment(Guid RoleId, string RoleName, string BusinessUnitName, bool IsMissing)
{
    public string DisplayName => IsMissing ? "(role không còn tồn tại)" : RoleName;

    public string BusinessUnitText => IsMissing ? RoleId.ToString() : BusinessUnitName;
}

/// <summary>Một form/dashboard kèm danh sách role được cấu hình nhìn thấy nó.</summary>
public sealed class FormRoleRow
{
    public Guid FormId { get; init; }
    public string FormName { get; init; } = "";
    public string EntityLogicalName { get; init; } = "";
    public string EntityDisplayName { get; init; } = "";
    public int FormType { get; init; }
    public string FormTypeText { get; init; } = "";
    public bool IsManaged { get; init; }
    public bool IsActive { get; init; }
    public FormVisibility Visibility { get; init; }
    public IReadOnlyList<FormRoleAssignment> Roles { get; init; } = [];

    public int RoleCount => Roles.Count;
    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
    public string StateText => IsActive ? "Active" : "Inactive";

    /// <summary>Dashboard không gắn với entity nào.</summary>
    public string EntityText => string.IsNullOrEmpty(EntityLogicalName) ? "—" : EntityDisplayName;

    public string VisibilityText => Visibility switch
    {
        FormVisibility.Everyone => "Mọi role (Everyone)",
        FormVisibility.SpecificRoles => $"Role cụ thể ({RoleCount})",
        FormVisibility.NotRoleScoped => "Không phân quyền theo role",
        _ => "⚠ Không đọc được",
    };

    /// <summary>Tóm tắt một dòng để hiện trong bảng.</summary>
    public string RolesText => Visibility switch
    {
        FormVisibility.Everyone => "Mọi role đều thấy form này",
        FormVisibility.NotRoleScoped => "Loại form này không gán được role – ai đọc được entity đều thấy",
        FormVisibility.Unreadable => "Cần mở Form settings trong D365 để kiểm tra",
        _ when Roles.Count == 0 => "Không role nào được gán – chỉ System Administrator thấy form này",
        _ => string.Join(", ", Roles.Take(12).Select(r => r.DisplayName))
             + (Roles.Count > 12 ? $" … (+{Roles.Count - 12})" : ""),
    };

    public bool HasRole(Guid rootRoleId) => Roles.Any(r => r.RoleId == rootRoleId);

    /// <summary>Form nghiệp vụ mở cho mọi role – đáng rà lại khi entity chứa dữ liệu nhạy cảm.</summary>
    public bool IsOpenToEveryone => Visibility == FormVisibility.Everyone;
}
