using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Messages;
using Microsoft.Xrm.Sdk.Metadata;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Truy vấn user, app, field security profile, business unit và chỉ mục phân quyền toàn môi trường.</summary>
public sealed partial class DataverseService
{
    private const string IndexCacheKey = "access-index";

    #region Users

    public async Task<List<UserInfo>> GetUsersAsync(CancellationToken ct = default)
    {
        const string fetch = """
            <fetch>
              <entity name="systemuser">
                <attribute name="systemuserid" />
                <attribute name="fullname" />
                <attribute name="domainname" />
                <attribute name="internalemailaddress" />
                <attribute name="title" />
                <attribute name="businessunitid" />
                <attribute name="isdisabled" />
                <attribute name="accessmode" />
                <attribute name="applicationid" />
                <order attribute="fullname" />
              </entity>
            </fetch>
            """;

        var users = (await FetchAllAsync(fetch, ct)).Select(MapUser).ToList();

        try
        {
            const string countFetch = """
                <fetch>
                  <entity name="systemuserroles">
                    <attribute name="systemuserid" />
                  </entity>
                </fetch>
                """;
            var counts = (await FetchAllAsync(countFetch, ct))
                .GroupBy(e => IdOf(e, "systemuserid"))
                .ToDictionary(g => g.Key, g => g.Count());
            foreach (var user in users)
                user.RoleCount = counts.GetValueOrDefault(user.Id);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Số role chỉ để hiển thị.
        }

        return users;
    }

    private static UserInfo MapUser(Entity e) => new()
    {
        Id = e.Id,
        FullName = e.GetAttributeValue<string>("fullname") ?? "",
        DomainName = e.GetAttributeValue<string>("domainname") ?? "",
        Email = e.GetAttributeValue<string>("internalemailaddress") ?? "",
        Title = e.GetAttributeValue<string>("title") ?? "",
        BusinessUnitId = e.GetAttributeValue<EntityReference>("businessunitid")?.Id ?? Guid.Empty,
        BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
        IsDisabled = e.GetAttributeValue<bool>("isdisabled"),
        AccessMode = e.GetAttributeValue<OptionSetValue>("accessmode")?.Value ?? 0,
        IsApplicationUser = e.Attributes.TryGetValue("applicationid", out var appId) && appId is Guid g && g != Guid.Empty,
    };

    public async Task<List<UserRoleAssignment>> GetUserDirectRolesAsync(Guid userId, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="role">
                <attribute name="roleid" />
                <attribute name="name" />
                <attribute name="businessunitid" />
                <attribute name="parentrootroleid" />
                <attribute name="ismanaged" />
                <attribute name="roletemplateid" />
                <order attribute="name" />
                <link-entity name="systemuserroles" from="roleid" to="roleid" intersect="true">
                  <filter>
                    <condition attribute="systemuserid" operator="eq" value="{userId}" />
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """;

        return (await FetchAllAsync(fetch, ct))
            .Select(e => new UserRoleAssignment
            {
                AssignedRoleId = e.Id,
                RootRoleId = e.GetAttributeValue<EntityReference>("parentrootroleid")?.Id ?? e.Id,
                Name = e.GetAttributeValue<string>("name") ?? "",
                BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                IsManaged = e.GetAttributeValue<bool>("ismanaged"),
                IsDirect = true,
                RoleTemplateId = IdOf(e, "roletemplateid") is var t && t != Guid.Empty ? t : null,
            })
            .DistinctBy(r => r.AssignedRoleId)
            .ToList();
    }

    public async Task<List<TeamInfo>> GetUserTeamsAsync(Guid userId, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="team">
                <attribute name="teamid" />
                <attribute name="name" />
                <attribute name="teamtype" />
                <attribute name="businessunitid" />
                <attribute name="isdefault" />
                <attribute name="azureactivedirectoryobjectid" />
                <order attribute="name" />
                <filter>
                  <condition attribute="teamtemplateid" operator="null" />
                </filter>
                <link-entity name="teammembership" from="teamid" to="teamid" intersect="true">
                  <filter>
                    <condition attribute="systemuserid" operator="eq" value="{userId}" />
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """;

        return (await FetchAllAsync(fetch, ct)).Select(MapTeam).DistinctBy(t => t.Id).ToList();
    }

    private static TeamInfo MapTeam(Entity e) => new()
    {
        Id = e.Id,
        Name = e.GetAttributeValue<string>("name") ?? "",
        TeamType = e.GetAttributeValue<OptionSetValue>("teamtype")?.Value ?? 0,
        BusinessUnitId = e.GetAttributeValue<EntityReference>("businessunitid")?.Id ?? Guid.Empty,
        BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
        IsDefault = e.GetAttributeValue<bool>("isdefault"),
        EntraObjectId = e.GetAttributeValue<Guid?>("azureactivedirectoryobjectid"),
    };

    /// <summary>Role của nhiều team cùng lúc (dùng cho quyền hiệu lực của user).</summary>
    public async Task<List<UserRoleAssignment>> GetRolesOfTeamsAsync(IReadOnlyCollection<TeamInfo> teams, CancellationToken ct = default)
    {
        if (teams.Count == 0)
            return [];

        var names = teams.ToDictionary(t => t.Id, t => t.Name);
        var result = new List<UserRoleAssignment>();
        foreach (var chunk in names.Keys.Chunk(200))
        {
            var fetch = $"""
                <fetch>
                  <entity name="role">
                    <attribute name="roleid" />
                    <attribute name="name" />
                    <attribute name="businessunitid" />
                    <attribute name="parentrootroleid" />
                    <attribute name="ismanaged" />
                    <attribute name="isinherited" />
                    <attribute name="roletemplateid" />
                    <order attribute="name" />
                    <link-entity name="teamroles" from="roleid" to="roleid" intersect="true" alias="tr">
                      <attribute name="teamid" />
                      <filter>
                        {InCondition("teamid", chunk)}
                      </filter>
                    </link-entity>
                  </entity>
                </fetch>
                """;

            foreach (var e in await FetchAllAsync(fetch, ct))
            {
                var teamId = Aliased<Guid>(e, "tr.teamid");
                result.Add(new UserRoleAssignment
                {
                    AssignedRoleId = e.Id,
                    RootRoleId = e.GetAttributeValue<EntityReference>("parentrootroleid")?.Id ?? e.Id,
                    Name = e.GetAttributeValue<string>("name") ?? "",
                    BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                    IsManaged = e.GetAttributeValue<bool>("ismanaged"),
                    IsDirect = false,
                    TeamId = teamId,
                    TeamName = names.GetValueOrDefault(teamId, ""),
                    IsInherited = (e.GetAttributeValue<OptionSetValue>("isinherited")?.Value ?? 1) != 0,
                    RoleTemplateId = IdOf(e, "roletemplateid") is var t && t != Guid.Empty ? t : null,
                });
            }
        }
        return result.DistinctBy(r => (r.AssignedRoleId, r.TeamId)).ToList();
    }

    #endregion

    #region Model-driven apps

    public async Task<List<AppModuleInfo>> GetAppModulesAsync(CancellationToken ct = default)
    {
        var apps = (await GetAllAppsAsync(ct))
            .Select(a => new AppModuleInfo
            {
                Id = a.Id,
                UniqueId = a.UniqueId,
                Name = a.Name,
                UniqueName = a.UniqueName,
                IsManaged = a.IsManaged,
                State = a.State,
            })
            .OrderBy(a => a.Name)
            .ToList();

        try
        {
            var links = await GetAppRoleLinksAsync(ct);
            foreach (var app in apps)
                app.RoleCount = links.Count(l => l.AppId == app.Id || l.AppId == app.UniqueId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Chỉ để hiển thị.
        }
        return apps;
    }

    /// <summary>Toàn bộ liên kết app ↔ role (roleid có thể là role gốc hoặc bản sao).</summary>
    public async Task<List<(Guid AppId, Guid RoleId)>> GetAppRoleLinksAsync(CancellationToken ct = default)
    {
        try
        {
            const string fetch = """
                <fetch>
                  <entity name="appmoduleroles">
                    <attribute name="appmoduleid" />
                    <attribute name="roleid" />
                  </entity>
                </fetch>
                """;
            return (await FetchAllAsync(fetch, ct)).Select(e => (IdOf(e, "appmoduleid"), IdOf(e, "roleid"))).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            const string linked = """
                <fetch>
                  <entity name="role">
                    <attribute name="roleid" />
                    <link-entity name="appmoduleroles" from="roleid" to="roleid" intersect="true">
                      <link-entity name="appmodule" from="appmoduleid" to="appmoduleid" alias="am">
                        <attribute name="appmoduleid" />
                      </link-entity>
                    </link-entity>
                  </entity>
                </fetch>
                """;
            return (await FetchAllAsync(linked, ct)).Select(e => (Aliased<Guid>(e, "am.appmoduleid"), e.Id)).ToList();
        }
    }

    #endregion

    #region Field security

    public async Task<List<FieldSecurityProfileInfo>> GetFieldSecurityProfilesAsync(CancellationToken ct = default)
    {
        const string fetch = """
            <fetch>
              <entity name="fieldsecurityprofile">
                <attribute name="fieldsecurityprofileid" />
                <attribute name="name" />
                <attribute name="description" />
                <attribute name="ismanaged" />
                <order attribute="name" />
              </entity>
            </fetch>
            """;

        return (await FetchAllAsync(fetch, ct)).Select(e => new FieldSecurityProfileInfo
        {
            Id = e.Id,
            Name = e.GetAttributeValue<string>("name") ?? "",
            Description = e.GetAttributeValue<string>("description") ?? "",
            IsManaged = e.GetAttributeValue<bool>("ismanaged"),
        }).ToList();
    }

    public async Task<List<UserInfo>> GetFieldProfileUsersAsync(Guid profileId, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="systemuser">
                <attribute name="systemuserid" />
                <attribute name="fullname" />
                <attribute name="domainname" />
                <attribute name="internalemailaddress" />
                <attribute name="title" />
                <attribute name="businessunitid" />
                <attribute name="isdisabled" />
                <attribute name="accessmode" />
                <attribute name="applicationid" />
                <order attribute="fullname" />
                <link-entity name="systemuserprofiles" from="systemuserid" to="systemuserid" intersect="true">
                  <filter>
                    <condition attribute="fieldsecurityprofileid" operator="eq" value="{profileId}" />
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """;
        return (await FetchAllAsync(fetch, ct)).Select(MapUser).DistinctBy(u => u.Id).ToList();
    }

    public async Task<List<TeamInfo>> GetFieldProfileTeamsAsync(Guid profileId, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="team">
                <attribute name="teamid" />
                <attribute name="name" />
                <attribute name="teamtype" />
                <attribute name="businessunitid" />
                <attribute name="isdefault" />
                <attribute name="azureactivedirectoryobjectid" />
                <order attribute="name" />
                <link-entity name="teamprofiles" from="teamid" to="teamid" intersect="true">
                  <filter>
                    <condition attribute="fieldsecurityprofileid" operator="eq" value="{profileId}" />
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """;
        return (await FetchAllAsync(fetch, ct)).Select(MapTeam).DistinctBy(t => t.Id).ToList();
    }

    public async Task<List<FieldPermissionRow>> GetFieldPermissionsAsync(Guid profileId, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="fieldpermission">
                <attribute name="entityname" />
                <attribute name="attributelogicalname" />
                <attribute name="canread" />
                <attribute name="cancreate" />
                <attribute name="canupdate" />
                <filter>
                  <condition attribute="fieldsecurityprofileid" operator="eq" value="{profileId}" />
                </filter>
              </entity>
            </fetch>
            """;

        var metadata = await GetEntityMetadataAsync(ct);
        var rows = new List<FieldPermissionRow>();
        foreach (var e in await FetchAllAsync(fetch, ct))
        {
            var entity = e.GetAttributeValue<string>("entityname") ?? "";
            var attribute = e.GetAttributeValue<string>("attributelogicalname") ?? "";
            var labels = await TryGetAttributeLabelsAsync(entity, ct);
            rows.Add(new FieldPermissionRow
            {
                Entity = entity,
                EntityDisplayName = metadata.GetValueOrDefault(entity)?.DisplayName ?? entity,
                Attribute = attribute,
                AttributeDisplayName = labels.GetValueOrDefault(attribute, attribute),
                CanRead = e.GetAttributeValue<OptionSetValue>("canread")?.Value == 4,
                CanCreate = e.GetAttributeValue<OptionSetValue>("cancreate")?.Value == 4,
                CanUpdate = e.GetAttributeValue<OptionSetValue>("canupdate")?.Value == 4,
            });
        }
        return rows.OrderBy(r => r.EntityDisplayName).ThenBy(r => r.AttributeDisplayName).ToList();
    }

    /// <summary>Field security profile của user: gán trực tiếp và qua team.</summary>
    public async Task<List<FieldProfileAssignment>> GetFieldProfilesOfUserAsync(Guid userId, IReadOnlyCollection<TeamInfo> teams, CancellationToken ct = default)
    {
        var result = new List<FieldProfileAssignment>();
        var direct = $"""
            <fetch>
              <entity name="fieldsecurityprofile">
                <attribute name="fieldsecurityprofileid" />
                <attribute name="name" />
                <link-entity name="systemuserprofiles" from="fieldsecurityprofileid" to="fieldsecurityprofileid" intersect="true">
                  <filter>
                    <condition attribute="systemuserid" operator="eq" value="{userId}" />
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """;
        result.AddRange((await FetchAllAsync(direct, ct)).Select(e => new FieldProfileAssignment
        {
            ProfileId = e.Id,
            Name = e.GetAttributeValue<string>("name") ?? "",
            IsDirect = true,
        }));

        if (teams.Count > 0)
        {
            var names = teams.ToDictionary(t => t.Id, t => t.Name);
            var viaTeams = $"""
                <fetch>
                  <entity name="fieldsecurityprofile">
                    <attribute name="fieldsecurityprofileid" />
                    <attribute name="name" />
                    <link-entity name="teamprofiles" from="fieldsecurityprofileid" to="fieldsecurityprofileid" intersect="true" alias="tp">
                      <attribute name="teamid" />
                      <filter>
                        {InCondition("teamid", names.Keys)}
                      </filter>
                    </link-entity>
                  </entity>
                </fetch>
                """;
            result.AddRange((await FetchAllAsync(viaTeams, ct)).Select(e => new FieldProfileAssignment
            {
                ProfileId = e.Id,
                Name = e.GetAttributeValue<string>("name") ?? "",
                IsDirect = false,
                TeamName = names.GetValueOrDefault(Aliased<Guid>(e, "tp.teamid"), ""),
            }));
        }

        return result.DistinctBy(r => (r.ProfileId, r.IsDirect, r.TeamName)).OrderBy(r => r.Name).ToList();
    }

    private Task<Dictionary<string, string>> TryGetAttributeLabelsAsync(string entity, CancellationToken ct) =>
        GetCachedAsync("attributes:" + entity, async () =>
        {
            try
            {
                var response = (RetrieveEntityResponse)await _client.ExecuteAsync(new RetrieveEntityRequest
                {
                    LogicalName = entity,
                    EntityFilters = EntityFilters.Attributes,
                }, ct);
                return response.EntityMetadata.Attributes
                    .Where(a => a.LogicalName is not null)
                    .ToDictionary(a => a.LogicalName, a => a.DisplayName?.UserLocalizedLabel?.Label ?? a.LogicalName, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
        }, ct);

    #endregion

    #region Business units

    public async Task<List<BusinessUnitInfo>> GetBusinessUnitsAsync(CancellationToken ct = default)
    {
        const string fetch = """
            <fetch>
              <entity name="businessunit">
                <attribute name="businessunitid" />
                <attribute name="name" />
                <attribute name="parentbusinessunitid" />
                <attribute name="isdisabled" />
                <order attribute="name" />
              </entity>
            </fetch>
            """;

        return (await FetchAllAsync(fetch, ct)).Select(e => new BusinessUnitInfo
        {
            Id = e.Id,
            Name = e.GetAttributeValue<string>("name") ?? "",
            ParentId = e.GetAttributeValue<EntityReference>("parentbusinessunitid")?.Id,
            IsDisabled = e.GetAttributeValue<bool>("isdisabled"),
        }).ToList();
    }

    #endregion

    #region Access index

    /// <summary>
    /// Tải (hoặc lấy từ cache) toàn bộ phân quyền của môi trường. Cache bị xóa sau mỗi thao tác thay đổi hoặc khi "Làm mới".
    /// </summary>
    public Task<AccessIndex> GetAccessIndexAsync(IProgress<string>? progress = null, CancellationToken ct = default) =>
        GetCachedAsync(IndexCacheKey, async () =>
        {
            progress?.Report("Đang tải danh sách role...");
            const string rolesFetch = """
                <fetch>
                  <entity name="role">
                    <attribute name="roleid" />
                    <attribute name="name" />
                    <attribute name="businessunitid" />
                    <attribute name="parentrootroleid" />
                    <attribute name="parentroleid" />
                    <attribute name="ismanaged" />
                    <attribute name="modifiedon" />
                    <attribute name="isinherited" />
                    <attribute name="roletemplateid" />
                  </entity>
                </fetch>
                """;
            var allRoles = await FetchAllAsync(rolesFetch, ct);
            var roots = new List<SecurityRoleInfo>();
            var copies = new Dictionary<Guid, List<RoleCopy>>();
            var copyToRoot = new Dictionary<Guid, Guid>();
            foreach (var e in allRoles)
            {
                var bu = e.GetAttributeValue<EntityReference>("businessunitid");
                var rootId = e.GetAttributeValue<EntityReference>("parentrootroleid")?.Id ?? e.Id;
                if (e.GetAttributeValue<EntityReference>("parentroleid") is null)
                {
                    rootId = e.Id;
                    roots.Add(new SecurityRoleInfo
                    {
                        Id = e.Id,
                        Name = e.GetAttributeValue<string>("name") ?? "",
                        BusinessUnitId = bu?.Id ?? Guid.Empty,
                        BusinessUnitName = bu?.Name ?? "",
                        IsManaged = e.GetAttributeValue<bool>("ismanaged"),
                        ModifiedOn = e.GetAttributeValue<DateTime?>("modifiedon")?.ToLocalTime(),
                        IsInherited = (e.GetAttributeValue<OptionSetValue>("isinherited")?.Value ?? 1) != 0,
                        RoleTemplateId = IdOf(e, "roletemplateid") is var tpl && tpl != Guid.Empty ? tpl : null,
                    });
                }
                copyToRoot[e.Id] = rootId;
                if (!copies.TryGetValue(rootId, out var list))
                    copies[rootId] = list = [];
                list.Add(new RoleCopy(e.Id, bu?.Id ?? Guid.Empty, bu?.Name ?? ""));
            }
            Guid Root(Guid roleId) => copyToRoot.GetValueOrDefault(roleId, roleId);

            progress?.Report($"Đang tải privilege của {roots.Count} role...");
            const string privilegesFetch = """
                <fetch>
                  <entity name="roleprivileges">
                    <attribute name="roleid" />
                    <attribute name="privilegeid" />
                    <attribute name="privilegedepthmask" />
                    <link-entity name="role" from="roleid" to="roleid">
                      <filter>
                        <condition attribute="parentroleid" operator="null" />
                      </filter>
                    </link-entity>
                  </entity>
                </fetch>
                """;
            var rolePrivileges = new Dictionary<Guid, Dictionary<Guid, PrivilegeDepth>>();
            foreach (var e in await FetchAllAsync(privilegesFetch, ct))
            {
                var roleId = IdOf(e, "roleid");
                if (!rolePrivileges.TryGetValue(roleId, out var map))
                    rolePrivileges[roleId] = map = [];
                var depth = EnumText.FromMask(e.GetAttributeValue<int>("privilegedepthmask"));
                var privilegeId = IdOf(e, "privilegeid");
                if (map.GetValueOrDefault(privilegeId) < depth)
                    map[privilegeId] = depth;
            }

            progress?.Report("Đang tải user, team, business unit...");
            var users = await GetUsersAsync(ct);
            var teams = await GetTeamsAsync(ct);
            var businessUnits = await GetBusinessUnitsAsync(ct);

            progress?.Report("Đang tải phân quyền user/team...");
            const string userRolesFetch = """
                <fetch>
                  <entity name="systemuserroles">
                    <attribute name="systemuserid" />
                    <attribute name="roleid" />
                  </entity>
                </fetch>
                """;
            var userRoles = (await FetchAllAsync(userRolesFetch, ct))
                .Select(e => (IdOf(e, "systemuserid"), Root(IdOf(e, "roleid"))))
                .Distinct()
                .ToList();

            const string teamRolesFetch = """
                <fetch>
                  <entity name="teamroles">
                    <attribute name="teamid" />
                    <attribute name="roleid" />
                  </entity>
                </fetch>
                """;
            var teamRoles = (await FetchAllAsync(teamRolesFetch, ct))
                .Select(e => (IdOf(e, "teamid"), Root(IdOf(e, "roleid"))))
                .Distinct()
                .ToList();

            progress?.Report("Đang tải thành viên team...");
            const string membershipFetch = """
                <fetch>
                  <entity name="teammembership">
                    <attribute name="teamid" />
                    <attribute name="systemuserid" />
                  </entity>
                </fetch>
                """;
            var knownTeams = teams.Select(t => t.Id).ToHashSet();
            var members = (await FetchAllAsync(membershipFetch, ct))
                .Select(e => (IdOf(e, "teamid"), IdOf(e, "systemuserid")))
                .Where(m => knownTeams.Contains(m.Item1))
                .Distinct()
                .ToList();

            return new AccessIndex
            {
                Roles = roots.OrderBy(r => r.Name).ToList(),
                RoleCopies = copies,
                CopyToRoot = copyToRoot,
                RolePrivileges = rolePrivileges,
                Users = users,
                Teams = teams,
                BusinessUnits = businessUnits,
                UserRoles = userRoles,
                TeamRoles = teamRoles,
                TeamMembers = members,
            };
        }, ct);

    #endregion
}
