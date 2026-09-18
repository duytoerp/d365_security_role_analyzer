using System.Collections.Concurrent;
using System.Security;
using System.Xml.Linq;
using Microsoft.PowerPlatform.Dataverse.Client;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Messages;
using Microsoft.Xrm.Sdk.Metadata;
using Microsoft.Xrm.Sdk.Query;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Truy vấn Dataverse / Dynamics 365. Metadata dùng chung (entity, privilege, form, view...)
/// được cache sau lần tải đầu tiên; gọi <see cref="ClearCache"/> để tải lại.
/// </summary>
public sealed partial class DataverseService : IDisposable
{
    private const int PageSize = 5000;

    /// <summary>Số kết quả tối đa cho hộp tìm user/team; hộp thoại có nút tải thêm để nâng giới hạn.</summary>
    public const int DefaultSearchTop = 100;

    private readonly ServiceClient _client;
    private readonly ConcurrentDictionary<string, Lazy<Task<object>>> _cache = new();

    private DataverseService(ServiceClient client)
    {
        _client = client;
    }

    public string OrganizationName => _client.ConnectedOrgFriendlyName ?? "";
    public string OrganizationUrl => _client.ConnectedOrgUriActual?.GetLeftPart(UriPartial.Authority) ?? "";
    public string CurrentUserName { get; private set; } = "";

    public static async Task<DataverseService> ConnectAsync(string connectionString, CancellationToken ct = default)
    {
        var client = await Task.Run(() => new ServiceClient(connectionString), ct);
        if (!client.IsReady)
        {
            var message = client.LastError;
            var inner = client.LastException;
            client.Dispose();
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(message) ? "Không thể kết nối tới Dataverse." : message, inner);
        }

        var service = new DataverseService(client);
        try
        {
            var who = (Microsoft.Crm.Sdk.Messages.WhoAmIResponse)await client.ExecuteAsync(new Microsoft.Crm.Sdk.Messages.WhoAmIRequest(), ct);
            var user = await client.RetrieveAsync("systemuser", who.UserId, new ColumnSet("fullname"), ct);
            service.CurrentUserName = user.GetAttributeValue<string>("fullname") ?? "";
        }
        catch
        {
            // Không bắt buộc: chỉ để hiển thị.
        }
        return service;
    }

    /// <summary>Khóa môi trường (host) dùng cho cache ổ đĩa, lịch sử và snapshot.</summary>
    public string EnvironmentKey => _client.ConnectedOrgUriActual?.Host ?? OrganizationName;

    /// <summary>Xóa cache trong bộ nhớ và (tùy chọn) cache metadata trên ổ đĩa.</summary>
    public void ClearCache(bool includeDisk = false)
    {
        _cache.Clear();
        if (includeDisk)
            DiskCache.Clear(EnvironmentKey);
    }

    public void Dispose() => _client.Dispose();

    #region Roles

    /// <summary>Lấy các role gốc (không lấy bản sao theo Business Unit con).</summary>
    public async Task<List<SecurityRoleInfo>> GetRolesAsync(CancellationToken ct = default)
    {
        const string fetch = """
            <fetch>
              <entity name="role">
                <attribute name="roleid" />
                <attribute name="name" />
                <attribute name="businessunitid" />
                <attribute name="ismanaged" />
                <attribute name="modifiedon" />
                <attribute name="isinherited" />
                <attribute name="roletemplateid" />
                <filter>
                  <condition attribute="parentroleid" operator="null" />
                </filter>
                <order attribute="name" />
              </entity>
            </fetch>
            """;

        var entities = await FetchAllAsync(fetch, ct);
        return entities.Select(e => new SecurityRoleInfo
        {
            Id = e.Id,
            Name = e.GetAttributeValue<string>("name") ?? "",
            BusinessUnitId = e.GetAttributeValue<EntityReference>("businessunitid")?.Id ?? Guid.Empty,
            BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
            IsManaged = e.GetAttributeValue<bool>("ismanaged"),
            ModifiedOn = e.GetAttributeValue<DateTime?>("modifiedon")?.ToLocalTime(),
            // isinherited: 0 = chỉ quyền team, 1 = quyền mức User + quyền team (mặc định).
            IsInherited = (e.GetAttributeValue<OptionSetValue>("isinherited")?.Value ?? 1) != 0,
            RoleTemplateId = IdOf(e, "roletemplateid") is var t && t != Guid.Empty ? t : null,
        }).ToList();
    }

    /// <summary>Role gốc + toàn bộ bản sao của nó ở các Business Unit.</summary>
    public async Task<List<RoleCopy>> GetRoleCopiesAsync(SecurityRoleInfo role, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="role">
                <attribute name="roleid" />
                <attribute name="businessunitid" />
                <filter type="or">
                  <condition attribute="roleid" operator="eq" value="{role.Id}" />
                  <condition attribute="parentrootroleid" operator="eq" value="{role.Id}" />
                </filter>
              </entity>
            </fetch>
            """;

        var entities = await FetchAllAsync(fetch, ct);
        var copies = entities
            .Select(e => new RoleCopy(
                e.Id,
                e.GetAttributeValue<EntityReference>("businessunitid")?.Id ?? Guid.Empty,
                e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? ""))
            .ToList();

        if (copies.All(c => c.RoleId != role.Id))
            copies.Add(new RoleCopy(role.Id, role.BusinessUnitId, role.BusinessUnitName));
        return copies;
    }

    #endregion

    #region Metadata & privileges

    public Task<Dictionary<string, EntityInfo>> GetEntityMetadataAsync(CancellationToken ct = default) =>
        GetCachedAsync("entities", async () =>
        {
            if (DiskCache.Load<Dictionary<string, EntityInfo>>(EnvironmentKey, "entities", DiskCache.DefaultMaxAge) is { Count: > 0 } cached)
                return new Dictionary<string, EntityInfo>(cached, StringComparer.OrdinalIgnoreCase);

            var response = (RetrieveAllEntitiesResponse)await _client.ExecuteAsync(new RetrieveAllEntitiesRequest
            {
                EntityFilters = EntityFilters.Entity,
                RetrieveAsIfPublished = false,
            }, ct);

            var result = response.EntityMetadata.ToDictionary(
                m => m.LogicalName,
                m => new EntityInfo
                {
                    LogicalName = m.LogicalName,
                    DisplayName = m.DisplayName?.UserLocalizedLabel?.Label ?? m.LogicalName,
                    IsCustom = m.IsCustomEntity == true,
                    IsIntersect = m.IsIntersect == true,
                    IsBpfEntity = m.IsBPFEntity == true,
                },
                StringComparer.OrdinalIgnoreCase);
            DiskCache.Save(EnvironmentKey, "entities", result);
            return result;
        }, ct);

    /// <summary>Danh mục toàn bộ privilege trong hệ thống (mỗi cặp privilege–entity là một dòng).</summary>
    public Task<List<PrivilegeDefinition>> GetPrivilegeCatalogAsync(CancellationToken ct = default) =>
        GetCachedAsync("privileges", async () =>
        {
            if (DiskCache.Load<List<PrivilegeDefinition>>(EnvironmentKey, "privileges", DiskCache.DefaultMaxAge) is { Count: > 0 } cached)
                return cached;

            const string fetch = """
                <fetch>
                  <entity name="privilege">
                    <attribute name="privilegeid" />
                    <attribute name="name" />
                    <attribute name="accessright" />
                    <attribute name="canbebasic" />
                    <attribute name="canbelocal" />
                    <attribute name="canbedeep" />
                    <attribute name="canbeglobal" />
                    <link-entity name="privilegeobjecttypecodes" from="privilegeid" to="privilegeid" link-type="outer" alias="potc">
                      <attribute name="objecttypecode" />
                    </link-entity>
                  </entity>
                </fetch>
                """;

            var entities = await FetchAllAsync(fetch, ct);
            var catalog = entities.Select(e =>
            {
                var entity = Aliased<string>(e, "potc.objecttypecode");
                if (string.IsNullOrWhiteSpace(entity) || entity.Equals("none", StringComparison.OrdinalIgnoreCase))
                    entity = null;

                return new PrivilegeDefinition
                {
                    Id = e.Id,
                    Name = e.GetAttributeValue<string>("name") ?? "",
                    AccessRight = (AccessRight)e.GetAttributeValue<int>("accessright"),
                    EntityLogicalName = entity,
                    CanBeBasic = e.GetAttributeValue<bool>("canbebasic"),
                    CanBeLocal = e.GetAttributeValue<bool>("canbelocal"),
                    CanBeDeep = e.GetAttributeValue<bool>("canbedeep"),
                    CanBeGlobal = e.GetAttributeValue<bool>("canbeglobal"),
                };
            }).ToList();
            DiskCache.Save(EnvironmentKey, "privileges", catalog);
            return catalog;
        }, ct);

    /// <summary>Privilege mà role đang có, key = privilegeid.</summary>
    public async Task<Dictionary<Guid, PrivilegeDepth>> GetRolePrivilegesAsync(Guid roleId, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="roleprivileges">
                <attribute name="privilegeid" />
                <attribute name="privilegedepthmask" />
                <filter>
                  <condition attribute="roleid" operator="eq" value="{roleId}" />
                </filter>
              </entity>
            </fetch>
            """;

        var result = new Dictionary<Guid, PrivilegeDepth>();
        foreach (var e in await FetchAllAsync(fetch, ct))
        {
            var privilegeId = IdOf(e, "privilegeid");
            var depth = EnumText.FromMask(e.GetAttributeValue<int>("privilegedepthmask"));
            if (!result.TryGetValue(privilegeId, out var existing) || existing < depth)
                result[privilegeId] = depth;
        }
        return result;
    }

    #endregion

    #region Users & teams

    public async Task<List<RoleUser>> GetRoleUsersAsync(IEnumerable<Guid> roleIds, CancellationToken ct = default)
    {
        var entities = await FetchChunkedAsync("roleid", roleIds, condition => $"""
            <fetch>
              <entity name="systemuser">
                <attribute name="systemuserid" />
                <attribute name="fullname" />
                <attribute name="domainname" />
                <attribute name="internalemailaddress" />
                <attribute name="businessunitid" />
                <attribute name="isdisabled" />
                <order attribute="fullname" />
                <link-entity name="systemuserroles" from="systemuserid" to="systemuserid" intersect="true" alias="sur">
                  <attribute name="roleid" />
                  <filter>
                    {condition}
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """, ct);

        return entities
            .Select(e => new RoleUser
            {
                Id = e.Id,
                FullName = e.GetAttributeValue<string>("fullname") ?? "",
                DomainName = e.GetAttributeValue<string>("domainname") ?? "",
                Email = e.GetAttributeValue<string>("internalemailaddress") ?? "",
                BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                IsDisabled = e.GetAttributeValue<bool>("isdisabled"),
                AssignedRoleId = Aliased<Guid>(e, "sur.roleid"),
            })
            .DistinctBy(u => (u.Id, u.AssignedRoleId))
            .ToList();
    }

    public async Task<List<RoleTeam>> GetRoleTeamsAsync(IEnumerable<Guid> roleIds, CancellationToken ct = default)
    {
        var entities = await FetchChunkedAsync("roleid", roleIds, condition => $"""
            <fetch>
              <entity name="team">
                <attribute name="teamid" />
                <attribute name="name" />
                <attribute name="teamtype" />
                <attribute name="businessunitid" />
                <attribute name="isdefault" />
                <order attribute="name" />
                <link-entity name="teamroles" from="teamid" to="teamid" intersect="true" alias="tr">
                  <attribute name="roleid" />
                  <filter>
                    {condition}
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """, ct);

        return entities
            .Select(e => new RoleTeam
            {
                Id = e.Id,
                Name = e.GetAttributeValue<string>("name") ?? "",
                TeamType = e.GetAttributeValue<OptionSetValue>("teamtype")?.Value ?? 0,
                BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                IsDefault = e.GetAttributeValue<bool>("isdefault"),
                AssignedRoleId = Aliased<Guid>(e, "tr.roleid"),
            })
            .DistinctBy(t => (t.Id, t.AssignedRoleId))
            .ToList();
    }

    /// <summary>Thành viên của các team (dùng để xác định user nhận role gián tiếp qua team).</summary>
    public async Task<List<RoleTeamUser>> GetTeamMembersAsync(IReadOnlyCollection<RoleTeam> teams, CancellationToken ct = default)
    {
        if (teams.Count == 0)
            return [];

        var teamNames = teams.GroupBy(t => t.Id).ToDictionary(g => g.Key, g => g.First().Name);
        var result = new List<RoleTeamUser>();

        // Chia nhỏ để tránh điều kiện IN quá dài.
        foreach (var chunk in teamNames.Keys.Chunk(200))
        {
            var fetch = $"""
                <fetch>
                  <entity name="systemuser">
                    <attribute name="systemuserid" />
                    <attribute name="fullname" />
                    <attribute name="domainname" />
                    <attribute name="businessunitid" />
                    <attribute name="isdisabled" />
                    <order attribute="fullname" />
                    <link-entity name="teammembership" from="systemuserid" to="systemuserid" intersect="true" alias="tm">
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
                var teamId = Aliased<Guid>(e, "tm.teamid");
                result.Add(new RoleTeamUser
                {
                    UserId = e.Id,
                    FullName = e.GetAttributeValue<string>("fullname") ?? "",
                    DomainName = e.GetAttributeValue<string>("domainname") ?? "",
                    BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                    IsDisabled = e.GetAttributeValue<bool>("isdisabled"),
                    TeamId = teamId,
                    TeamName = teamNames.GetValueOrDefault(teamId, ""),
                });
            }
        }

        return result.DistinctBy(r => (r.UserId, r.TeamId)).ToList();
    }

    public async Task<List<PrincipalSearchResult>> SearchUsersAsync(string text, int top = DefaultSearchTop, CancellationToken ct = default)
    {
        var like = SecurityElement.Escape($"%{text.Trim()}%");
        var fetch = $"""
            <fetch top="{top}">
              <entity name="systemuser">
                <attribute name="systemuserid" />
                <attribute name="fullname" />
                <attribute name="domainname" />
                <attribute name="businessunitid" />
                <order attribute="fullname" />
                <filter>
                  <condition attribute="isdisabled" operator="eq" value="0" />
                  <filter type="or">
                    <condition attribute="fullname" operator="like" value="{like}" />
                    <condition attribute="domainname" operator="like" value="{like}" />
                  </filter>
                </filter>
              </entity>
            </fetch>
            """;

        var response = await _client.RetrieveMultipleAsync(new FetchExpression(fetch), ct);
        return response.Entities.Select(e => new PrincipalSearchResult
        {
            Id = e.Id,
            Name = e.GetAttributeValue<string>("fullname") ?? "",
            Detail = e.GetAttributeValue<string>("domainname") ?? "",
            BusinessUnitId = e.GetAttributeValue<EntityReference>("businessunitid")?.Id ?? Guid.Empty,
            BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
        }).ToList();
    }

    public async Task<List<PrincipalSearchResult>> SearchTeamsAsync(string text, int top = DefaultSearchTop, CancellationToken ct = default)
    {
        var like = SecurityElement.Escape($"%{text.Trim()}%");
        var fetch = $"""
            <fetch top="{top}">
              <entity name="team">
                <attribute name="teamid" />
                <attribute name="name" />
                <attribute name="teamtype" />
                <attribute name="businessunitid" />
                <order attribute="name" />
                <filter>
                  <condition attribute="name" operator="like" value="{like}" />
                </filter>
              </entity>
            </fetch>
            """;

        var response = await _client.RetrieveMultipleAsync(new FetchExpression(fetch), ct);
        return response.Entities.Select(e => new PrincipalSearchResult
        {
            Id = e.Id,
            Name = e.GetAttributeValue<string>("name") ?? "",
            Detail = new RoleTeam { TeamType = e.GetAttributeValue<OptionSetValue>("teamtype")?.Value ?? 0 }.TeamTypeText,
            BusinessUnitId = e.GetAttributeValue<EntityReference>("businessunitid")?.Id ?? Guid.Empty,
            BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
        }).ToList();
    }

    #endregion

    #region Team management

    /// <summary>Danh sách team (bỏ qua access team tự sinh từ Access Team Template).</summary>
    public async Task<List<TeamInfo>> GetTeamsAsync(CancellationToken ct = default)
    {
        const string fetch = """
            <fetch>
              <entity name="team">
                <attribute name="teamid" />
                <attribute name="name" />
                <attribute name="teamtype" />
                <attribute name="businessunitid" />
                <attribute name="isdefault" />
                <attribute name="azureactivedirectoryobjectid" />
                <attribute name="administratorid" />
                <attribute name="description" />
                <filter>
                  <condition attribute="teamtemplateid" operator="null" />
                </filter>
                <order attribute="name" />
              </entity>
            </fetch>
            """;

        var teams = (await FetchAllAsync(fetch, ct)).Select(e => new TeamInfo
        {
            Id = e.Id,
            Name = e.GetAttributeValue<string>("name") ?? "",
            TeamType = e.GetAttributeValue<OptionSetValue>("teamtype")?.Value ?? 0,
            BusinessUnitId = e.GetAttributeValue<EntityReference>("businessunitid")?.Id ?? Guid.Empty,
            BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
            IsDefault = e.GetAttributeValue<bool>("isdefault"),
            EntraObjectId = e.GetAttributeValue<Guid?>("azureactivedirectoryobjectid"),
            AdministratorName = e.GetAttributeValue<EntityReference>("administratorid")?.Name ?? "",
            Description = e.GetAttributeValue<string>("description") ?? "",
        }).ToList();

        try
        {
            const string countFetch = """
                <fetch>
                  <entity name="teamroles">
                    <attribute name="teamid" />
                  </entity>
                </fetch>
                """;
            var counts = (await FetchAllAsync(countFetch, ct))
                .GroupBy(e => IdOf(e, "teamid"))
                .ToDictionary(g => g.Key, g => g.Count());
            foreach (var team in teams)
                team.RoleCount = counts.GetValueOrDefault(team.Id);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Số role chỉ để hiển thị trong danh sách.
        }

        return teams;
    }

    public async Task<List<TeamRoleAssignment>> GetTeamRolesAsync(Guid teamId, CancellationToken ct = default)
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
                <order attribute="name" />
                <link-entity name="teamroles" from="roleid" to="roleid" intersect="true">
                  <filter>
                    <condition attribute="teamid" operator="eq" value="{teamId}" />
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """;

        return (await FetchAllAsync(fetch, ct))
            .Select(e => new TeamRoleAssignment
            {
                AssignedRoleId = e.Id,
                RootRoleId = e.GetAttributeValue<EntityReference>("parentrootroleid")?.Id ?? e.Id,
                Name = e.GetAttributeValue<string>("name") ?? "",
                BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                IsManaged = e.GetAttributeValue<bool>("ismanaged"),
                IsInherited = (e.GetAttributeValue<OptionSetValue>("isinherited")?.Value ?? 1) != 0,
            })
            .DistinctBy(r => r.AssignedRoleId)
            .ToList();
    }

    public async Task<List<TeamMember>> GetTeamMembersAsync(Guid teamId, CancellationToken ct = default)
    {
        var fetch = $"""
            <fetch>
              <entity name="systemuser">
                <attribute name="systemuserid" />
                <attribute name="fullname" />
                <attribute name="domainname" />
                <attribute name="internalemailaddress" />
                <attribute name="businessunitid" />
                <attribute name="isdisabled" />
                <order attribute="fullname" />
                <link-entity name="teammembership" from="systemuserid" to="systemuserid" intersect="true">
                  <filter>
                    <condition attribute="teamid" operator="eq" value="{teamId}" />
                  </filter>
                </link-entity>
              </entity>
            </fetch>
            """;

        return (await FetchAllAsync(fetch, ct))
            .Select(e => new TeamMember
            {
                Id = e.Id,
                FullName = e.GetAttributeValue<string>("fullname") ?? "",
                DomainName = e.GetAttributeValue<string>("domainname") ?? "",
                Email = e.GetAttributeValue<string>("internalemailaddress") ?? "",
                BusinessUnitName = e.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                IsDisabled = e.GetAttributeValue<bool>("isdisabled"),
            })
            .DistinctBy(m => m.Id)
            .ToList();
    }

    #endregion

    #region Components

    public sealed record AppInfo(Guid Id, Guid UniqueId, string Name, string UniqueName, bool IsManaged, int State);

    public sealed record FormInfo(
        Guid Id, string Name, string Entity, int Type, bool IsManaged, int ActivationState,
        HashSet<Guid> RoleIds, bool VisibleToEveryone, bool DisplayConditionsUnreadable = false);

    public sealed record ViewInfo(Guid Id, string Name, string Entity, int QueryType, bool IsDefault, bool IsManaged, int State);

    public sealed record ChartInfo(Guid Id, string Name, string Entity, bool IsManaged);

    public sealed record BpfInfo(Guid Id, string Name, string UniqueName, string PrimaryEntity, bool IsManaged, int State);

    public sealed record CustomApiInfo(Guid Id, string Name, string UniqueName, string ExecutePrivilegeName, string BoundEntity, bool IsManaged);

    public async Task<List<AppInfo>> GetAppsForRoleAsync(IReadOnlyCollection<Guid> roleIds, CancellationToken ct = default)
    {
        HashSet<Guid> appIds;
        try
        {
            appIds = (await FetchChunkedAsync("roleid", roleIds, condition => $"""
                <fetch>
                  <entity name="appmoduleroles">
                    <attribute name="appmoduleid" />
                    <attribute name="roleid" />
                    <filter>
                      {condition}
                    </filter>
                  </entity>
                </fetch>
                """, ct))
                .Select(e => IdOf(e, "appmoduleid"))
                .Where(id => id != Guid.Empty)
                .ToHashSet();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Một số môi trường không cho RetrieveMultiple trực tiếp trên bảng trung gian → dùng link-entity.
            // Nếu cách này cũng lỗi thì để lỗi nổi lên, tránh im lặng nuốt lỗi phân quyền.
            appIds = (await FetchChunkedAsync("roleid", roleIds, condition => $"""
                <fetch distinct="true">
                  <entity name="appmodule">
                    <attribute name="appmoduleid" />
                    <link-entity name="appmoduleroles" from="appmoduleid" to="appmoduleid" intersect="true">
                      <filter>
                        {condition}
                      </filter>
                    </link-entity>
                  </entity>
                </fetch>
                """, ct)).Select(e => e.Id).ToHashSet();
        }

        var apps = await GetAllAppsAsync(ct);
        // Tùy phiên bản, appmoduleroles tham chiếu appmoduleid hoặc appmoduleidunique.
        return apps.Where(a => appIds.Contains(a.Id) || appIds.Contains(a.UniqueId)).ToList();
    }

    internal Task<List<AppInfo>> GetAllAppsAsync(CancellationToken ct) =>
        GetCachedAsync("apps", async () =>
        {
            const string fetch = """
                <fetch>
                  <entity name="appmodule">
                    <attribute name="appmoduleid" />
                    <attribute name="appmoduleidunique" />
                    <attribute name="name" />
                    <attribute name="uniquename" />
                    <attribute name="ismanaged" />
                    <attribute name="statecode" />
                  </entity>
                </fetch>
                """;

            return (await FetchAllAsync(fetch, ct)).Select(e => new AppInfo(
                e.Id,
                e.GetAttributeValue<Guid>("appmoduleidunique"),
                e.GetAttributeValue<string>("name") ?? "",
                e.GetAttributeValue<string>("uniquename") ?? "",
                e.GetAttributeValue<bool>("ismanaged"),
                e.GetAttributeValue<OptionSetValue>("statecode")?.Value ?? 0)).ToList();
        }, ct);

    public Task<List<FormInfo>> GetFormsAsync(CancellationToken ct = default) =>
        GetCachedAsync("forms", async () =>
        {
            // 0 Dashboard, 2 Main, 6 Quick View, 7 Quick Create, 10 Interactive Dashboard, 12 Main Interactive, 103 Power BI Dashboard
            const string fetch = """
                <fetch>
                  <entity name="systemform">
                    <attribute name="formid" />
                    <attribute name="name" />
                    <attribute name="objecttypecode" />
                    <attribute name="type" />
                    <attribute name="ismanaged" />
                    <attribute name="formactivationstate" />
                    <attribute name="displayconditions" />
                    <filter>
                      <condition attribute="type" operator="in">
                        <value>0</value><value>2</value><value>6</value><value>7</value>
                        <value>10</value><value>12</value><value>103</value>
                      </condition>
                    </filter>
                  </entity>
                </fetch>
                """;

            return (await FetchAllAsync(fetch, ct)).Select(e =>
            {
                var readable = TryParseDisplayConditions(e.GetAttributeValue<string>("displayconditions"), out var parsed);
                return new FormInfo(
                    e.Id,
                    e.GetAttributeValue<string>("name") ?? "",
                    e.GetAttributeValue<string>("objecttypecode") ?? "none",
                    e.GetAttributeValue<OptionSetValue>("type")?.Value ?? -1,
                    e.GetAttributeValue<bool>("ismanaged"),
                    e.GetAttributeValue<OptionSetValue>("formactivationstate")?.Value ?? 1,
                    parsed.RoleIds,
                    parsed.Everyone,
                    !readable);
            }).ToList();
        }, ct);

    public Task<List<ViewInfo>> GetViewsAsync(CancellationToken ct = default) =>
        GetCachedAsync("views", async () =>
        {
            // 0 Public, 1 Advanced Find, 2 Associated, 4 Quick Find, 64 Lookup
            const string fetch = """
                <fetch>
                  <entity name="savedquery">
                    <attribute name="savedqueryid" />
                    <attribute name="name" />
                    <attribute name="returnedtypecode" />
                    <attribute name="querytype" />
                    <attribute name="isdefault" />
                    <attribute name="ismanaged" />
                    <attribute name="statecode" />
                    <filter>
                      <condition attribute="querytype" operator="in">
                        <value>0</value><value>1</value><value>2</value><value>4</value><value>64</value>
                      </condition>
                    </filter>
                  </entity>
                </fetch>
                """;

            return (await FetchAllAsync(fetch, ct)).Select(e => new ViewInfo(
                e.Id,
                e.GetAttributeValue<string>("name") ?? "",
                e.GetAttributeValue<string>("returnedtypecode") ?? "",
                e.GetAttributeValue<int>("querytype"),
                e.GetAttributeValue<bool>("isdefault"),
                e.GetAttributeValue<bool>("ismanaged"),
                e.GetAttributeValue<OptionSetValue>("statecode")?.Value ?? 0)).ToList();
        }, ct);

    public Task<List<ChartInfo>> GetChartsAsync(CancellationToken ct = default) =>
        GetCachedAsync("charts", async () =>
        {
            const string fetch = """
                <fetch>
                  <entity name="savedqueryvisualization">
                    <attribute name="savedqueryvisualizationid" />
                    <attribute name="name" />
                    <attribute name="primaryentitytypecode" />
                    <attribute name="ismanaged" />
                  </entity>
                </fetch>
                """;

            return (await FetchAllAsync(fetch, ct)).Select(e => new ChartInfo(
                e.Id,
                e.GetAttributeValue<string>("name") ?? "",
                e.GetAttributeValue<string>("primaryentitytypecode") ?? "",
                e.GetAttributeValue<bool>("ismanaged"))).ToList();
        }, ct);

    public Task<List<BpfInfo>> GetBusinessProcessFlowsAsync(CancellationToken ct = default) =>
        GetCachedAsync("bpf", async () =>
        {
            const string fetch = """
                <fetch>
                  <entity name="workflow">
                    <attribute name="workflowid" />
                    <attribute name="name" />
                    <attribute name="uniquename" />
                    <attribute name="primaryentity" />
                    <attribute name="ismanaged" />
                    <attribute name="statecode" />
                    <filter>
                      <condition attribute="category" operator="eq" value="4" />
                      <condition attribute="type" operator="eq" value="1" />
                    </filter>
                  </entity>
                </fetch>
                """;

            return (await FetchAllAsync(fetch, ct)).Select(e => new BpfInfo(
                e.Id,
                e.GetAttributeValue<string>("name") ?? "",
                e.GetAttributeValue<string>("uniquename") ?? "",
                e.GetAttributeValue<string>("primaryentity") ?? "",
                e.GetAttributeValue<bool>("ismanaged"),
                e.GetAttributeValue<OptionSetValue>("statecode")?.Value ?? 0)).ToList();
        }, ct);

    public Task<List<CustomApiInfo>> GetCustomApisAsync(CancellationToken ct = default) =>
        GetCachedAsync("customapi", async () =>
        {
            const string fetch = """
                <fetch>
                  <entity name="customapi">
                    <attribute name="customapiid" />
                    <attribute name="name" />
                    <attribute name="uniquename" />
                    <attribute name="executeprivilegename" />
                    <attribute name="boundentitylogicalname" />
                    <attribute name="ismanaged" />
                    <filter>
                      <condition attribute="executeprivilegename" operator="not-null" />
                    </filter>
                  </entity>
                </fetch>
                """;

            return (await FetchAllAsync(fetch, ct)).Select(e => new CustomApiInfo(
                e.Id,
                e.GetAttributeValue<string>("name") ?? "",
                e.GetAttributeValue<string>("uniquename") ?? "",
                e.GetAttributeValue<string>("executeprivilegename") ?? "",
                e.GetAttributeValue<string>("boundentitylogicalname") ?? "",
                e.GetAttributeValue<bool>("ismanaged"))).ToList();
        }, ct);

    /// <summary>
    /// displayconditions có dạng &lt;Roles&gt;&lt;Role Id="{guid}" /&gt;&lt;/Roles&gt; hoặc chứa &lt;Everyone /&gt;.
    /// Rỗng nghĩa là form hiển thị cho mọi role.
    /// </summary>
    /// <summary>
    /// Trả về false khi displayconditions có nội dung nhưng không phân tích được. Khi đó
    /// <b>không</b> được suy ra là "mọi role đều thấy" – component sẽ được đánh dấu là không xác định.
    /// </summary>
    internal static bool TryParseDisplayConditions(string? xml, out (HashSet<Guid> RoleIds, bool Everyone) result)
    {
        var ids = new HashSet<Guid>();
        if (string.IsNullOrWhiteSpace(xml))
        {
            result = (ids, true);
            return true;
        }

        try
        {
            var root = XElement.Parse(xml);
            var everyone = root.DescendantsAndSelf().Any(x => x.Name.LocalName.Equals("Everyone", StringComparison.OrdinalIgnoreCase));
            foreach (var role in root.DescendantsAndSelf().Where(x => x.Name.LocalName.Equals("Role", StringComparison.OrdinalIgnoreCase)))
            {
                var idAttr = role.Attributes().FirstOrDefault(a => a.Name.LocalName.Equals("Id", StringComparison.OrdinalIgnoreCase));
                if (idAttr != null && Guid.TryParse(idAttr.Value, out var id))
                    ids.Add(id);
            }
            result = (ids, everyone || ids.Count == 0);
            return true;
        }
        catch
        {
            result = (ids, false);
            return false;
        }
    }

    #endregion

    #region Helpers

    /// <summary>
    /// Dữ liệu dùng chung, chỉ tải một lần. Nếu tác vụ tải đang dùng chung bị <b>người gọi khác</b> hủy,
    /// người gọi hiện tại sẽ tự tải lại bằng token của mình thay vì nhận lỗi hủy oan.
    /// </summary>
    private async Task<T> GetCachedAsync<T>(string key, Func<Task<T>> factory, CancellationToken ct = default)
        where T : class
    {
        for (var attempt = 0; ; attempt++)
        {
            var lazy = _cache.GetOrAdd(key, _ => new Lazy<Task<object>>(async () => await factory()));
            try
            {
                // WaitAsync: ta ngừng chờ mà không kéo theo những người đang chờ cùng dữ liệu.
                return (T)await lazy.Value.WaitAsync(ct);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested && attempt == 0)
            {
                // Tác vụ dùng chung bị hủy bởi người gọi khác – bỏ khỏi cache rồi tải lại.
                _cache.TryRemove(key, out _);
            }
            catch
            {
                // Lần tải lỗi không được giữ lại trong cache, để lần sau còn thử lại được.
                _cache.TryRemove(key, out _);
                throw;
            }
        }
    }

    private async Task<List<Entity>> FetchAllAsync(string fetchXml, CancellationToken ct)
    {
        var doc = XDocument.Parse(fetchXml);
        var fetch = doc.Root!;
        var result = new List<Entity>();
        var page = 1;
        string? cookie = null;

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            fetch.SetAttributeValue("page", page);
            fetch.SetAttributeValue("count", PageSize);
            if (cookie != null)
                fetch.SetAttributeValue("paging-cookie", cookie);

            var response = await _client.RetrieveMultipleAsync(
                new FetchExpression(doc.ToString(SaveOptions.DisableFormatting)), ct);
            result.AddRange(response.Entities);

            if (!response.MoreRecords)
                break;
            page++;
            cookie = response.PagingCookie;
        }
        return result;
    }

    private static string InCondition(string attribute, IEnumerable<Guid> values)
    {
        var items = string.Concat(values.Distinct().Select(v => $"<value>{v}</value>"));
        return $"""<condition attribute="{attribute}" operator="in">{items}</condition>""";
    }

    /// <summary>Số Id tối đa trong một điều kiện <c>in</c>; Dataverse giới hạn độ dài FetchXML.</summary>
    private const int InChunkSize = 200;

    /// <summary>
    /// Chạy một truy vấn có điều kiện <c>in</c> theo từng lô Id để FetchXML không vượt giới hạn độ dài.
    /// <paramref name="build"/> nhận điều kiện đã dựng sẵn cho lô hiện tại.
    /// </summary>
    private async Task<List<Entity>> FetchChunkedAsync(
        string attribute, IEnumerable<Guid> ids, Func<string, string> build, CancellationToken ct)
    {
        var distinct = ids.Distinct().ToList();
        if (distinct.Count == 0)
            return [];

        var result = new List<Entity>();
        foreach (var chunk in distinct.Chunk(InChunkSize))
            result.AddRange(await FetchAllAsync(build(InCondition(attribute, chunk)), ct));
        return result;
    }

    /// <summary>Cột ID trên bảng trung gian có thể là Guid hoặc EntityReference.</summary>
    private static Guid IdOf(Entity entity, string name) =>
        entity.Attributes.TryGetValue(name, out var value)
            ? value switch
            {
                Guid id => id,
                EntityReference reference => reference.Id,
                _ => Guid.Empty,
            }
            : Guid.Empty;

    private static T? Aliased<T>(Entity entity, string name)
    {
        if (entity.Attributes.TryGetValue(name, out var value) && value is AliasedValue aliased)
        {
            return aliased.Value switch
            {
                T typed => typed,
                EntityReference reference when typeof(T) == typeof(Guid) => (T)(object)reference.Id,
                _ => default,
            };
        }
        return default;
    }

    #endregion
}
