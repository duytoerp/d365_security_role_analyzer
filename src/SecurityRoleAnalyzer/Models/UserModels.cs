namespace SecurityRoleAnalyzer.Models;

public sealed class UserInfo
{
    public Guid Id { get; init; }
    public string FullName { get; init; } = "";
    public string DomainName { get; init; } = "";
    public string Email { get; init; } = "";
    public string Title { get; init; } = "";
    public Guid BusinessUnitId { get; init; }
    public string BusinessUnitName { get; init; } = "";
    public bool IsDisabled { get; init; }
    /// <summary>systemuser.accessmode: 0 Read-Write, 1 Administrative, 2 Read, 3 Support, 4 Non-interactive, 5 Delegated Admin.</summary>
    public int AccessMode { get; init; }
    public bool IsApplicationUser { get; init; }
    /// <summary>Số role gán trực tiếp; -1 nếu chưa xác định.</summary>
    public int RoleCount { get; set; } = -1;

    public string StatusText => IsDisabled ? "Disabled" : "Enabled";

    public string AccessModeText => IsApplicationUser ? "Application user" : AccessMode switch
    {
        0 => "Read-Write",
        1 => "Administrative",
        2 => "Read",
        3 => "Support User",
        4 => "Non-interactive",
        5 => "Delegated Admin",
        _ => AccessMode.ToString(),
    };

    public string ListCaption =>
        $"{BusinessUnitName} · {(string.IsNullOrEmpty(DomainName) ? AccessModeText : DomainName)}"
        + (RoleCount >= 0 ? $" · {RoleCount} role" : "")
        + (IsDisabled ? " · Disabled" : "");

    public override string ToString() => FullName;
}

/// <summary>Role user nhận được: trực tiếp hoặc thông qua team.</summary>
public sealed class UserRoleAssignment
{
    public Guid AssignedRoleId { get; init; }
    public Guid RootRoleId { get; init; }
    public string Name { get; init; } = "";
    public string BusinessUnitName { get; init; } = "";
    public bool IsManaged { get; init; }
    public bool IsDirect { get; init; }
    public Guid? TeamId { get; init; }
    public string TeamName { get; init; } = "";
    /// <summary>Role này cũng được nhận từ nguồn khác (trực tiếp và/hoặc team khác).</summary>
    public bool IsDuplicated { get; set; }
    /// <summary>
    /// Với role qua team: false = "Team privileges only", quyền chỉ dùng được trên record của team.
    /// Role gán trực tiếp luôn là true.
    /// </summary>
    public bool IsInherited { get; init; } = true;
    /// <summary>Id template của role hệ thống; dùng để nhận diện không phụ thuộc ngôn ngữ.</summary>
    public Guid? RoleTemplateId { get; init; }

    /// <summary>Quyền qua team nhưng không áp dụng cho record của chính user.</summary>
    public bool IsTeamScopedOnly => !IsDirect && !IsInherited;

    public bool IsSystemAdministrator =>
        RoleTemplateId == RoleTemplates.SystemAdministrator || RoleTemplates.IsAdminName(Name);

    public string SourceText => IsDirect
        ? "Trực tiếp"
        : $"Qua team: {TeamName}" + (IsInherited ? "" : " (chỉ record của team)");
    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
}

public sealed class FieldProfileAssignment
{
    public Guid ProfileId { get; init; }
    public string Name { get; init; } = "";
    public bool IsDirect { get; init; }
    public string TeamName { get; init; } = "";

    public string SourceText => IsDirect ? "Trực tiếp" : $"Qua team: {TeamName}";
}

public sealed class UserAnalysis
{
    public required UserInfo User { get; init; }
    public List<UserRoleAssignment> DirectRoles { get; init; } = [];
    public List<TeamInfo> Teams { get; init; } = [];
    public List<UserRoleAssignment> TeamRoles { get; init; } = [];
    public List<EntityPrivilegeRow> EntityRows { get; init; } = [];
    public List<MiscPrivilegeRow> MiscPrivileges { get; init; } = [];
    public List<RoleComponent> Apps { get; init; } = [];
    public List<FieldProfileAssignment> FieldProfiles { get; init; } = [];
    public List<AnalysisFinding> Findings { get; init; } = [];
    public List<string> Warnings { get; init; } = [];

    public IEnumerable<UserRoleAssignment> AllRoles => DirectRoles.Concat(TeamRoles);
}

/// <summary>Tùy chọn khi sao chép quyền giữa các user.</summary>
public sealed class CopyAccessOptions
{
    public bool Roles { get; set; } = true;
    public bool Teams { get; set; } = true;
    public bool FieldProfiles { get; set; } = true;
    /// <summary>Gỡ role/team/profile trực tiếp của user đích mà user nguồn không có.</summary>
    public bool RemoveExtra { get; set; }
}
