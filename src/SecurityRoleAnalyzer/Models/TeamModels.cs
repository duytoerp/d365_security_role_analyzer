namespace SecurityRoleAnalyzer.Models;

public static class TeamTypes
{
    public const string All = "Tất cả loại";

    public static readonly string[] Names = ["Owner", "Access", "Entra ID Security Group", "Entra ID Office Group"];

    public static string ToText(int teamType) =>
        teamType >= 0 && teamType < Names.Length ? Names[teamType] : teamType.ToString();

    /// <summary>Team đồng bộ thành viên từ Microsoft Entra ID.</summary>
    public static bool IsEntraGroup(int teamType) => teamType is 2 or 3;
}

public sealed class TeamInfo
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public int TeamType { get; init; }
    public Guid BusinessUnitId { get; init; }
    public string BusinessUnitName { get; init; } = "";
    public bool IsDefault { get; init; }
    public Guid? EntraObjectId { get; init; }
    public string AdministratorName { get; init; } = "";
    public string Description { get; init; } = "";
    /// <summary>Số role đang gán; -1 nếu chưa xác định.</summary>
    public int RoleCount { get; set; } = -1;

    public string TeamTypeText => TeamTypes.ToText(TeamType);

    public string ListCaption =>
        $"{BusinessUnitName} · {TeamTypeText}" + (RoleCount >= 0 ? $" · {RoleCount} role" : "") + (IsDefault ? " · Default" : "");

    /// <summary>Default team của BU hoặc team Entra ID: thành viên do hệ thống quản lý.</summary>
    public bool CanManageMembers => !IsDefault && !TeamTypes.IsEntraGroup(TeamType);

    public override string ToString() => Name;
}

/// <summary>Một security role đang gán cho team.</summary>
public sealed class TeamRoleAssignment
{
    /// <summary>Id bản sao role (theo BU của team) thực sự được gán.</summary>
    public Guid AssignedRoleId { get; init; }
    /// <summary>Id role gốc (dùng để mở role / đọc privilege).</summary>
    public Guid RootRoleId { get; init; }
    public string Name { get; init; } = "";
    public string BusinessUnitName { get; init; } = "";
    public bool IsManaged { get; init; }
    /// <summary>
    /// false = "Team privileges only": quyền chỉ áp dụng trên record do team sở hữu,
    /// thành viên không nhận quyền mức User cho record của chính mình.
    /// </summary>
    public bool IsInherited { get; init; } = true;
    public int GrantedEntityCount { get; set; }
    public int GrantedMiscCount { get; set; }

    public string ManagedText => IsManaged ? "Managed" : "Unmanaged";
    public string InheritanceText => IsInherited ? "User + Team" : "Chỉ record của team";
}

public sealed class TeamMember
{
    public Guid Id { get; init; }
    public string FullName { get; init; } = "";
    public string DomainName { get; init; } = "";
    public string Email { get; init; } = "";
    public string BusinessUnitName { get; init; } = "";
    public bool IsDisabled { get; init; }

    public string StatusText => IsDisabled ? "Disabled" : "Enabled";
}

public sealed class TeamAnalysis
{
    public required TeamInfo Team { get; init; }
    public List<TeamRoleAssignment> Roles { get; init; } = [];
    public List<TeamMember> Members { get; init; } = [];
    /// <summary>Quyền hiệu lực: gộp (lấy mức cao nhất) từ tất cả role của team.</summary>
    public List<EntityPrivilegeRow> EntityRows { get; init; } = [];
    public List<MiscPrivilegeRow> MiscPrivileges { get; init; } = [];
    public List<RoleComponent> Apps { get; init; } = [];
    public List<AnalysisFinding> Findings { get; init; } = [];
    public List<string> Warnings { get; init; } = [];
}
