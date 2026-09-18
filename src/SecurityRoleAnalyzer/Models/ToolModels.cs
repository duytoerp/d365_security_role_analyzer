using System.ComponentModel;

namespace SecurityRoleAnalyzer.Models;

#region Snapshot

public sealed class EnvironmentSnapshot
{
    public string Environment { get; set; } = "";
    public DateTime CreatedOn { get; set; } = DateTime.Now;
    public string CreatedBy { get; set; } = "";
    public List<SnapshotRole> Roles { get; set; } = [];
    public List<SnapshotLink> UserRoles { get; set; } = [];
    public List<SnapshotLink> TeamRoles { get; set; } = [];
    public List<SnapshotLink> TeamMembers { get; set; } = [];

    public string Title => $"{Environment} – {CreatedOn:dd/MM/yyyy HH:mm}";
}

public sealed class SnapshotRole
{
    public string Name { get; set; } = "";
    public string BusinessUnit { get; set; } = "";
    public bool IsManaged { get; set; }
    /// <summary>Tên privilege → mức (chỉ các privilege được cấp).</summary>
    public SortedDictionary<string, PrivilegeDepth> Privileges { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Liên kết theo tên (so sánh được giữa các môi trường).</summary>
public sealed class SnapshotLink
{
    /// <summary>Khóa của principal: username (user) hoặc tên team.</summary>
    public string Principal { get; set; } = "";
    public string PrincipalName { get; set; } = "";
    /// <summary>Tên role (UserRoles/TeamRoles) hoặc username (TeamMembers).</summary>
    public string Target { get; set; } = "";
}

public sealed class SnapshotDiffRow
{
    public string Category { get; init; } = "";
    public string ChangeType { get; init; } = "";
    public string Item { get; init; } = "";
    public string Detail { get; init; } = "";
    public string Before { get; init; } = "";
    public string After { get; init; } = "";

    /// <summary>Mức quyền ở bản B, dùng khi áp diff (chỉ có với dòng privilege).</summary>
    public PrivilegeDepth TargetDepth { get; init; }

    /// <summary>Áp được sang môi trường khác hay không; hiện chỉ hỗ trợ privilege của role.</summary>
    public bool CanApply { get; init; }
}

/// <summary>Kết quả áp diff snapshot vào môi trường đang kết nối.</summary>
public sealed class SnapshotApplyResult
{
    public int RolesUpdated { get; set; }
    public int RolesCreated { get; set; }
    public int PrivilegesApplied { get; set; }
    public List<string> Errors { get; set; } = [];
    public List<string> Skipped { get; set; } = [];

    public string Summary =>
        $"Đã áp {PrivilegesApplied} privilege trên {RolesUpdated} role"
        + (RolesCreated > 0 ? $" (tạo mới {RolesCreated} role)" : "")
        + (Skipped.Count > 0 ? $", bỏ qua {Skipped.Count}" : "")
        + (Errors.Count > 0 ? $", {Errors.Count} lỗi" : "") + ".";
}

#endregion

#region Import

public static class ImportActions
{
    public const string AssignRole = "Gán role";
    public const string RemoveRole = "Gỡ role";
    public const string AddToTeam = "Thêm vào team";
    public const string RemoveFromTeam = "Gỡ khỏi team";

    public static readonly string[] All = [AssignRole, RemoveRole, AddToTeam, RemoveFromTeam];
}

public sealed class ImportRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    public int RowNumber { get; init; }
    public string PrincipalType { get; init; } = "";
    public string Principal { get; init; } = "";
    public string Action { get; init; } = "";
    public string Target { get; init; } = "";

    // Kết quả phân giải
    public bool IsTeam { get; set; }
    public Guid PrincipalId { get; set; }
    public string PrincipalDisplay { get; set; } = "";
    public Guid PrincipalBusinessUnitId { get; set; }
    public string PrincipalBusinessUnitName { get; set; } = "";
    public Guid TargetId { get; set; }
    public string TargetDisplay { get; set; } = "";

    public string Status
    {
        get;
        set { field = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Status))); }
    } = "";

    public string Message
    {
        get;
        set { field = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Message))); }
    } = "";

    public bool IsValid => Status == ImportStatus.Valid;
}

public static class ImportStatus
{
    public const string Valid = "Hợp lệ";
    public const string Skipped = "Bỏ qua";
    public const string Error = "Lỗi";
    public const string Done = "Đã thực hiện";
    public const string Failed = "Thất bại";
}

#endregion

#region Lookup & review

public sealed class LookupRoleRow
{
    public Guid RoleId { get; init; }
    public string Name { get; init; } = "";
    public bool IsManaged { get; init; }
    public PrivilegeDepth Depth { get; init; }
    public int DirectUserCount { get; init; }
    public int TeamCount { get; init; }

    public string DepthText => Depth.ToText();
    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
}

public sealed class ReviewUserRow
{
    public required UserInfo User { get; init; }
    public string DirectRoles { get; init; } = "";
    public string TeamRoles { get; init; } = "";
    public int DirectRoleCount { get; init; }
    public int TeamRoleCount { get; init; }
    public int EffectiveRoleCount { get; init; }
    public int TeamCount { get; init; }
    public bool IsSystemAdministrator { get; init; }
    public string Flags { get; init; } = "";

    public bool HasIssue => Flags.Length > 0;
}

public sealed class ReviewRoleRow
{
    public required SecurityRoleInfo Role { get; init; }
    public int DirectUserCount { get; init; }
    public int TeamCount { get; init; }
    public int EffectiveUserCount { get; init; }
    public int DisabledUserCount { get; init; }
    public bool IsUnused => DirectUserCount == 0 && TeamCount == 0;
}

public sealed class BulkChangeRow
{
    public Guid RoleId { get; init; }
    public string RoleName { get; init; } = "";
    public Guid PrivilegeId { get; init; }
    public string PrivilegeName { get; init; } = "";
    public string Entity { get; init; } = "";
    public string Right { get; init; } = "";
    public PrivilegeDepth Current { get; init; }
    public PrivilegeDepth Target { get; init; }
    public string Note { get; init; } = "";

    public string CurrentText => Current.ToText();
    public string TargetText => Target.ToText();
}

/// <summary>Bản sao lưu privilege của một role (file JSON).</summary>
public sealed class PrivilegeBackup
{
    public string Environment { get; set; } = "";
    public Guid RoleId { get; set; }
    public string RoleName { get; set; } = "";
    public DateTime CreatedOn { get; set; } = DateTime.Now;
    public string Reason { get; set; } = "";
    public List<PrivilegeBackupItem> Privileges { get; set; } = [];
}

public sealed class PrivilegeBackupItem
{
    public Guid PrivilegeId { get; set; }
    public string Name { get; set; } = "";
    public PrivilegeDepth Depth { get; set; }
}

#endregion

#region Audit log của Dataverse

/// <summary>Một dòng trong audit log của Dataverse liên quan tới phân quyền.</summary>
public sealed class AuditEntry
{
    public Guid Id { get; init; }
    public DateTime CreatedOn { get; init; }
    public string Action { get; init; } = "";
    public string EntityName { get; init; } = "";
    public string TargetName { get; init; } = "";
    public Guid TargetId { get; init; }
    public string UserName { get; init; } = "";

    public string TimeText => CreatedOn.ToString("dd/MM/yyyy HH:mm");
}

#endregion

#region Định nghĩa role (xuất / nhập giữa môi trường)

/// <summary>
/// Định nghĩa đầy đủ của một role để mang sang môi trường khác: privilege, app được thêm vào,
/// field security profile. Privilege khớp theo tên (Id khác nhau giữa các môi trường).
/// </summary>
public sealed class RoleDefinition
{
    public string Name { get; set; } = "";
    public string SourceEnvironment { get; set; } = "";
    public Guid SourceRoleId { get; set; }
    public string BusinessUnitName { get; set; } = "";
    public bool IsInherited { get; set; } = true;
    public DateTime ExportedOn { get; set; } = DateTime.Now;
    public List<PrivilegeBackupItem> Privileges { get; set; } = [];
    /// <summary>Unique name của Model-driven App có role này.</summary>
    public List<string> Apps { get; set; } = [];
    /// <summary>Tên Field Security Profile (chỉ để tham khảo; profile gán cho user/team, không gán cho role).</summary>
    public List<string> Notes { get; set; } = [];

    public int GrantedCount => Privileges.Count(p => p.Depth > PrivilegeDepth.None);
}

/// <summary>Kết quả áp một định nghĩa role vào môi trường hiện tại.</summary>
public sealed class RoleImportResult
{
    public Guid RoleId { get; set; }
    public bool Created { get; set; }
    public int PrivilegesApplied { get; set; }
    public List<string> MissingPrivileges { get; set; } = [];
    public List<string> MissingApps { get; set; } = [];
    public int AppsLinked { get; set; }

    public string Summary =>
        $"{(Created ? "Đã tạo role mới" : "Đã cập nhật role")}: {PrivilegesApplied} privilege, {AppsLinked} app"
        + (MissingPrivileges.Count > 0 ? $", {MissingPrivileges.Count} privilege không có trên môi trường này" : "")
        + (MissingApps.Count > 0 ? $", {MissingApps.Count} app không tìm thấy" : "");
}

#endregion
