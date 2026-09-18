using Microsoft.Crm.Sdk.Messages;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Messages;
using Microsoft.Xrm.Sdk.Metadata;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Quyền trên một bản ghi cụ thể: quyền hiệu lực của user, danh sách chia sẻ,
/// access team template và hierarchy security.
/// </summary>
public sealed partial class DataverseService
{
    #region Quyền trên một bản ghi

    /// <summary>Quyền thực tế Dataverse cấp cho user trên bản ghi này (đã tính cả role, share, hierarchy, team).</summary>
    public async Task<AccessRight[]> GetPrincipalAccessAsync(EntityReference record, Guid userId, CancellationToken ct = default)
    {
        var response = (RetrievePrincipalAccessResponse)await _client.ExecuteAsync(new RetrievePrincipalAccessRequest
        {
            Target = record,
            Principal = new EntityReference(UserEntity, userId),
        }, ct);

        return SplitAccessRights(response.AccessRights);
    }

    /// <summary>Những user/team được chia sẻ bản ghi này và quyền được chia sẻ.</summary>
    public async Task<List<RecordShareRow>> GetRecordSharesAsync(EntityReference record, CancellationToken ct = default)
    {
        var response = (RetrieveSharedPrincipalsAndAccessResponse)await _client.ExecuteAsync(
            new RetrieveSharedPrincipalsAndAccessRequest { Target = record }, ct);

        return response.PrincipalAccesses.Select(p => new RecordShareRow
        {
            PrincipalId = p.Principal.Id,
            PrincipalType = p.Principal.LogicalName,
            PrincipalName = p.Principal.Name ?? "",
            Rights = SplitAccessRights(p.AccessMask),
        }).ToList();
    }

    /// <summary>Thông tin chủ sở hữu và Business Unit của bản ghi, dùng để giải thích quyền theo mức.</summary>
    public async Task<RecordOwnerInfo?> GetRecordOwnerAsync(string entityLogicalName, Guid recordId, CancellationToken ct = default)
    {
        var metadata = (RetrieveEntityResponse)await _client.ExecuteAsync(new RetrieveEntityRequest
        {
            LogicalName = entityLogicalName,
            EntityFilters = EntityFilters.Entity,
        }, ct);

        var ownership = metadata.EntityMetadata.OwnershipType ?? OwnershipTypes.None;
        var columns = new List<string>();
        if (ownership.HasFlag(OwnershipTypes.UserOwned) || ownership.HasFlag(OwnershipTypes.TeamOwned))
        {
            columns.Add("ownerid");
            columns.Add("owningbusinessunit");
        }

        var primaryName = metadata.EntityMetadata.PrimaryNameAttribute;
        if (!string.IsNullOrEmpty(primaryName))
            columns.Add(primaryName);

        var record = await _client.RetrieveAsync(entityLogicalName, recordId,
            new Microsoft.Xrm.Sdk.Query.ColumnSet(columns.ToArray()), ct);

        var owner = record.GetAttributeValue<EntityReference>("ownerid");
        return new RecordOwnerInfo
        {
            EntityLogicalName = entityLogicalName,
            EntityDisplayName = metadata.EntityMetadata.DisplayName?.UserLocalizedLabel?.Label ?? entityLogicalName,
            RecordId = recordId,
            RecordName = primaryName is not null ? record.GetAttributeValue<string>(primaryName) ?? "" : "",
            OwnerId = owner?.Id ?? Guid.Empty,
            OwnerName = owner?.Name ?? "",
            OwnerIsTeam = owner?.LogicalName == TeamEntity,
            OwningBusinessUnitId = record.GetAttributeValue<EntityReference>("owningbusinessunit")?.Id ?? Guid.Empty,
            OwningBusinessUnitName = record.GetAttributeValue<EntityReference>("owningbusinessunit")?.Name ?? "",
            IsOrganizationOwned = ownership.HasFlag(OwnershipTypes.OrganizationOwned),
        };
    }

    private static AccessRight[] SplitAccessRights(Microsoft.Crm.Sdk.Messages.AccessRights mask)
    {
        var map = new (Microsoft.Crm.Sdk.Messages.AccessRights Flag, AccessRight Right)[]
        {
            (Microsoft.Crm.Sdk.Messages.AccessRights.ReadAccess, AccessRight.Read),
            (Microsoft.Crm.Sdk.Messages.AccessRights.WriteAccess, AccessRight.Write),
            (Microsoft.Crm.Sdk.Messages.AccessRights.DeleteAccess, AccessRight.Delete),
            (Microsoft.Crm.Sdk.Messages.AccessRights.AppendAccess, AccessRight.Append),
            (Microsoft.Crm.Sdk.Messages.AccessRights.AppendToAccess, AccessRight.AppendTo),
            (Microsoft.Crm.Sdk.Messages.AccessRights.AssignAccess, AccessRight.Assign),
            (Microsoft.Crm.Sdk.Messages.AccessRights.ShareAccess, AccessRight.Share),
        };
        return map.Where(m => mask.HasFlag(m.Flag)).Select(m => m.Right).ToArray();
    }

    #endregion

    #region Access team template

    /// <summary>
    /// Access team template: mẫu quyền cho team truy cập tự sinh theo từng bản ghi
    /// (bảng con "Access Team" trên form). Đây là nguồn quyền mà phân tích theo role không thấy được.
    /// </summary>
    public Task<List<AccessTeamTemplateInfo>> GetAccessTeamTemplatesAsync(CancellationToken ct = default) =>
        GetCachedAsync("teamtemplates", async () =>
        {
            const string fetch = """
                <fetch>
                  <entity name="teamtemplate">
                    <attribute name="teamtemplateid" />
                    <attribute name="teamtemplatename" />
                    <attribute name="objecttypecode" />
                    <attribute name="defaultaccessrightsmask" />
                    <attribute name="description" />
                    <order attribute="teamtemplatename" />
                  </entity>
                </fetch>
                """;

            var templates = (await FetchAllAsync(fetch, ct)).Select(e => new AccessTeamTemplateInfo
            {
                Id = e.Id,
                Name = e.GetAttributeValue<string>("teamtemplatename") ?? "",
                EntityTypeCode = e.GetAttributeValue<int>("objecttypecode"),
                AccessRightsMask = e.GetAttributeValue<int>("defaultaccessrightsmask"),
                Description = e.GetAttributeValue<string>("description") ?? "",
            }).ToList();

            await FillTemplateEntityNamesAsync(templates, ct);
            return templates;
        }, ct);

    /// <summary>objecttypecode là số; đổi sang tên bảng bằng metadata để hiển thị.</summary>
    private async Task FillTemplateEntityNamesAsync(List<AccessTeamTemplateInfo> templates, CancellationToken ct)
    {
        if (templates.Count == 0)
            return;

        try
        {
            var response = (RetrieveAllEntitiesResponse)await _client.ExecuteAsync(new RetrieveAllEntitiesRequest
            {
                EntityFilters = EntityFilters.Entity,
                RetrieveAsIfPublished = false,
            }, ct);

            var byCode = response.EntityMetadata
                .Where(m => m.ObjectTypeCode is not null)
                .GroupBy(m => m.ObjectTypeCode!.Value)
                .ToDictionary(g => g.Key, g => g.First());

            foreach (var template in templates)
            {
                if (!byCode.TryGetValue(template.EntityTypeCode, out var metadata))
                    continue;
                template.EntityLogicalName = metadata.LogicalName;
                template.EntityDisplayName = metadata.DisplayName?.UserLocalizedLabel?.Label ?? metadata.LogicalName;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorLog.Write("Đọc tên bảng cho access team template", ex);
        }
    }

    #endregion

    #region Hierarchy security

    /// <summary>Cấu hình hierarchy security của môi trường (manager hierarchy hoặc position hierarchy).</summary>
    public async Task<HierarchySecurityInfo> GetHierarchySecurityAsync(CancellationToken ct = default)
    {
        const string fetch = """
            <fetch top="1">
              <entity name="hierarchysecurityconfiguration">
                <attribute name="ishierarchymodelenabled" />
                <attribute name="hierarchymodel" />
                <attribute name="depth" />
              </entity>
            </fetch>
            """;

        try
        {
            var entity = (await FetchAllAsync(fetch, ct)).FirstOrDefault();
            if (entity is null)
                return new HierarchySecurityInfo();

            return new HierarchySecurityInfo
            {
                IsEnabled = entity.GetAttributeValue<bool>("ishierarchymodelenabled"),
                // hierarchymodel: 0 = Manager hierarchy, 1 = Custom position hierarchy.
                UsesPositions = (entity.GetAttributeValue<OptionSetValue>("hierarchymodel")?.Value ?? 0) == 1,
                Depth = entity.GetAttributeValue<int>("depth"),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Bảng này không có ở mọi phiên bản; coi như chưa bật.
            ErrorLog.Write("Đọc cấu hình hierarchy security", ex);
            return new HierarchySecurityInfo { IsReadable = false };
        }
    }

    /// <summary>Chuỗi quản lý của user (dùng khi hierarchy security bật theo manager).</summary>
    public async Task<List<UserInfo>> GetManagerChainAsync(Guid userId, int maxDepth = 10, CancellationToken ct = default)
    {
        var chain = new List<UserInfo>();
        var currentId = userId;

        for (var i = 0; i < maxDepth; i++)
        {
            ct.ThrowIfCancellationRequested();
            var fetch = $"""
                <fetch top="1">
                  <entity name="systemuser">
                    <attribute name="systemuserid" />
                    <attribute name="parentsystemuserid" />
                    <filter>
                      <condition attribute="systemuserid" operator="eq" value="{currentId}" />
                    </filter>
                  </entity>
                </fetch>
                """;

            var entity = (await FetchAllAsync(fetch, ct)).FirstOrDefault();
            var manager = entity?.GetAttributeValue<EntityReference>("parentsystemuserid");
            if (manager is null)
                break;

            var details = await _client.RetrieveAsync(UserEntity, manager.Id,
                new Microsoft.Xrm.Sdk.Query.ColumnSet("systemuserid", "fullname", "domainname", "businessunitid", "isdisabled"), ct);

            chain.Add(new UserInfo
            {
                Id = details.Id,
                FullName = details.GetAttributeValue<string>("fullname") ?? "",
                DomainName = details.GetAttributeValue<string>("domainname") ?? "",
                BusinessUnitName = details.GetAttributeValue<EntityReference>("businessunitid")?.Name ?? "",
                IsDisabled = details.GetAttributeValue<bool>("isdisabled"),
            });

            currentId = manager.Id;
        }

        return chain;
    }

    #endregion
}
