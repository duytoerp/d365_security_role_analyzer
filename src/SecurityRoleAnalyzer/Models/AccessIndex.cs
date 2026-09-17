namespace SecurityRoleAnalyzer.Models;

/// <summary>
/// Ảnh chụp toàn bộ phân quyền của môi trường: role, privilege của role, gán role cho user/team và thành viên team.
/// Dùng cho tra cứu ngược, rà soát quyền, snapshot, import và chế độ Apps / Business Units.
/// Mọi Id role ở đây là Id role gốc (đã quy đổi từ bản sao theo BU).
/// </summary>
public sealed class AccessIndex
{
    public List<SecurityRoleInfo> Roles { get; init; } = [];
    public Dictionary<Guid, List<RoleCopy>> RoleCopies { get; init; } = [];
    /// <summary>Id bất kỳ bản sao role → Id role gốc.</summary>
    public Dictionary<Guid, Guid> CopyToRoot { get; init; } = [];
    public Dictionary<Guid, Dictionary<Guid, PrivilegeDepth>> RolePrivileges { get; init; } = [];
    public List<UserInfo> Users { get; init; } = [];
    public List<TeamInfo> Teams { get; init; } = [];
    public List<BusinessUnitInfo> BusinessUnits { get; init; } = [];
    public List<(Guid UserId, Guid RoleId)> UserRoles { get; init; } = [];
    public List<(Guid TeamId, Guid RoleId)> TeamRoles { get; init; } = [];
    public List<(Guid TeamId, Guid UserId)> TeamMembers { get; init; } = [];
    public DateTime LoadedOn { get; init; } = DateTime.Now;

    private Dictionary<Guid, SecurityRoleInfo>? _roleById;
    private Dictionary<Guid, UserInfo>? _userById;
    private Dictionary<Guid, TeamInfo>? _teamById;
    private ILookup<Guid, Guid>? _rolesByUser;
    private ILookup<Guid, Guid>? _rolesByTeam;
    private ILookup<Guid, Guid>? _teamsByUser;
    private ILookup<Guid, Guid>? _usersByTeam;
    private ILookup<Guid, Guid>? _usersByRole;
    private ILookup<Guid, Guid>? _teamsByRole;

    public Dictionary<Guid, SecurityRoleInfo> RoleById => _roleById ??= Roles.GroupBy(r => r.Id).ToDictionary(g => g.Key, g => g.First());
    public Dictionary<Guid, UserInfo> UserById => _userById ??= Users.GroupBy(u => u.Id).ToDictionary(g => g.Key, g => g.First());
    public Dictionary<Guid, TeamInfo> TeamById => _teamById ??= Teams.GroupBy(t => t.Id).ToDictionary(g => g.Key, g => g.First());

    public IEnumerable<Guid> DirectRolesOf(Guid userId) => (_rolesByUser ??= UserRoles.ToLookup(x => x.UserId, x => x.RoleId))[userId];
    public IEnumerable<Guid> RolesOfTeam(Guid teamId) => (_rolesByTeam ??= TeamRoles.ToLookup(x => x.TeamId, x => x.RoleId))[teamId];
    public IEnumerable<Guid> TeamsOf(Guid userId) => (_teamsByUser ??= TeamMembers.ToLookup(x => x.UserId, x => x.TeamId))[userId];
    public IEnumerable<Guid> MembersOf(Guid teamId) => (_usersByTeam ??= TeamMembers.ToLookup(x => x.TeamId, x => x.UserId))[teamId];
    public IEnumerable<Guid> UsersWithDirectRole(Guid roleId) => (_usersByRole ??= UserRoles.ToLookup(x => x.RoleId, x => x.UserId))[roleId];
    public IEnumerable<Guid> TeamsWithRole(Guid roleId) => (_teamsByRole ??= TeamRoles.ToLookup(x => x.RoleId, x => x.TeamId))[roleId];

    public string RoleName(Guid roleId) => RoleById.TryGetValue(roleId, out var role) ? role.Name : roleId.ToString();
    public string TeamName(Guid teamId) => TeamById.TryGetValue(teamId, out var team) ? team.Name : teamId.ToString();

    /// <summary>Mọi role hiệu lực của user kèm nguồn (null = trực tiếp, Guid = team).</summary>
    public IEnumerable<(Guid RoleId, Guid? TeamId)> EffectiveRolesOf(Guid userId)
    {
        foreach (var roleId in DirectRolesOf(userId))
            yield return (roleId, null);
        foreach (var teamId in TeamsOf(userId))
        foreach (var roleId in RolesOfTeam(teamId))
            yield return (roleId, teamId);
    }

    /// <summary>Mọi user nhận role (trực tiếp hoặc qua team), kèm nguồn.</summary>
    public IEnumerable<(Guid UserId, Guid? TeamId)> EffectiveUsersOf(Guid roleId)
    {
        foreach (var userId in UsersWithDirectRole(roleId))
            yield return (userId, null);
        foreach (var teamId in TeamsWithRole(roleId))
        foreach (var userId in MembersOf(teamId))
            yield return (userId, teamId);
    }

    public PrivilegeDepth DepthOf(Guid roleId, Guid privilegeId) =>
        RolePrivileges.TryGetValue(roleId, out var privileges) ? privileges.GetValueOrDefault(privilegeId) : PrivilegeDepth.None;
}
