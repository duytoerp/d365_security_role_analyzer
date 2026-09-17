namespace SecurityRoleAnalyzer.Models;

public sealed class RoleUser
{
    public Guid Id { get; init; }
    public string FullName { get; init; } = "";
    public string DomainName { get; init; } = "";
    public string Email { get; init; } = "";
    public string BusinessUnitName { get; init; } = "";
    public bool IsDisabled { get; init; }
    /// <summary>Role (bản sao theo BU) thực sự được gán cho user.</summary>
    public Guid AssignedRoleId { get; init; }
    public bool AlsoViaTeam { get; set; }

    public string StatusText => IsDisabled ? "Disabled" : "Enabled";
}

public sealed class RoleTeam
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public int TeamType { get; init; }
    public string BusinessUnitName { get; init; } = "";
    public bool IsDefault { get; init; }
    public Guid AssignedRoleId { get; init; }
    public int MemberCount { get; set; }

    public string TeamTypeText => TeamTypes.ToText(TeamType);
}

/// <summary>User nhận role gián tiếp thông qua team.</summary>
public sealed class RoleTeamUser
{
    public Guid UserId { get; init; }
    public string FullName { get; init; } = "";
    public string DomainName { get; init; } = "";
    public string BusinessUnitName { get; init; } = "";
    public bool IsDisabled { get; init; }
    public Guid TeamId { get; init; }
    public string TeamName { get; init; } = "";
    public bool AlsoDirect { get; set; }

    public string StatusText => IsDisabled ? "Disabled" : "Enabled";
}

/// <summary>Kết quả tìm kiếm user/team để gán role.</summary>
public sealed class PrincipalSearchResult
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public string Detail { get; init; } = "";
    public Guid BusinessUnitId { get; init; }
    public string BusinessUnitName { get; init; } = "";
}
