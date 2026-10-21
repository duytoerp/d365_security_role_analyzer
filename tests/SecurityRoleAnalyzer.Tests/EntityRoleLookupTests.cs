using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class EntityRoleLookupTests
{
    private static PrivilegeDefinition Privilege(string entity, AccessRight right, string? name = null) => new()
    {
        Id = Guid.NewGuid(),
        Name = name ?? $"prv{right}{entity}",
        AccessRight = right,
        EntityLogicalName = entity,
        CanBeBasic = true, CanBeLocal = true, CanBeDeep = true, CanBeGlobal = true,
    };

    private static readonly PrivilegeDefinition ReadAccount = Privilege("account", AccessRight.Read);
    private static readonly PrivilegeDefinition DeleteAccount = Privilege("account", AccessRight.Delete);
    private static readonly PrivilegeDefinition ReadContact = Privilege("contact", AccessRight.Read);
    private static readonly PrivilegeDefinition ExportToExcel = new() { Id = Guid.NewGuid(), Name = "prvExportToExcel", AccessRight = AccessRight.Read };

    private static readonly List<PrivilegeDefinition> Catalog = [ReadAccount, DeleteAccount, ReadContact, ExportToExcel];

    private static (AccessIndex Index, SecurityRoleInfo Sales, SecurityRoleInfo Admin, SecurityRoleInfo Viewer) Build()
    {
        var sales = new SecurityRoleInfo { Id = Guid.NewGuid(), Name = "Sales" };
        var admin = new SecurityRoleInfo { Id = Guid.NewGuid(), Name = "Admin", IsManaged = true };
        var viewer = new SecurityRoleInfo { Id = Guid.NewGuid(), Name = "Contact Viewer" };
        var index = new AccessIndex { Roles = [sales, admin, viewer] };
        index.RolePrivileges[sales.Id] = new() { [ReadAccount.Id] = PrivilegeDepth.BusinessUnit };
        index.RolePrivileges[admin.Id] = new()
        {
            [ReadAccount.Id] = PrivilegeDepth.Organization,
            [DeleteAccount.Id] = PrivilegeDepth.Organization,
            [ReadContact.Id] = PrivilegeDepth.Organization,
            [ExportToExcel.Id] = PrivilegeDepth.Organization,
        };
        index.RolePrivileges[viewer.Id] = new() { [ReadContact.Id] = PrivilegeDepth.User };
        index.UserRoles.Add((Guid.NewGuid(), sales.Id));
        index.UserRoles.Add((Guid.NewGuid(), sales.Id));
        index.TeamRoles.Add((Guid.NewGuid(), admin.Id));
        return (index, sales, admin, viewer);
    }

    [Fact]
    public void Find_returns_depth_of_each_right_and_orders_roles_with_most_access_first()
    {
        var (index, sales, admin, viewer) = Build();

        var rows = EntityRoleLookup.Find(index, Catalog, "account");

        Assert.Equal([admin.Id, sales.Id, viewer.Id], rows.Select(r => r.RoleId));
        var adminRow = rows[0];
        Assert.Equal(PrivilegeDepth.Organization, adminRow.Read.Depth);
        Assert.Equal(PrivilegeDepth.Organization, adminRow.Delete.Depth);
        Assert.False(adminRow.Create.Exists);
        Assert.Equal(1, adminRow.TeamCount);

        var salesRow = rows[1];
        Assert.Equal(PrivilegeDepth.BusinessUnit, salesRow.Read.Depth);
        Assert.Equal(PrivilegeDepth.None, salesRow.Delete.Depth);
        Assert.True(salesRow.Delete.Exists);
        Assert.Equal(2, salesRow.DirectUserCount);
        Assert.Equal("prvReadaccount", salesRow.Read.PrivilegeName);

        Assert.False(rows[2].HasAnyPrivilege);
    }

    [Fact]
    public void Entity_name_is_case_insensitive()
    {
        var (index, _, _, _) = Build();
        Assert.Equal(2, EntityRoleLookup.Find(index, Catalog, "ACCOUNT").Count(r => r.HasAnyPrivilege));
    }

    [Fact]
    public void Matches_filters_by_right_and_minimum_depth()
    {
        var (index, _, _, _) = Build();
        var rows = EntityRoleLookup.Find(index, Catalog, "account");
        string[] Names(AccessRight right, PrivilegeDepth min) =>
            rows.Where(r => EntityRoleLookup.Matches(r, right, min)).Select(r => r.Name).ToArray();

        Assert.Equal(["Admin", "Sales"], Names(AccessRight.None, PrivilegeDepth.User));
        Assert.Equal(["Admin"], Names(AccessRight.Delete, PrivilegeDepth.User));
        Assert.Equal(["Admin"], Names(AccessRight.Read, PrivilegeDepth.ParentChild));
        Assert.Equal(["Admin", "Sales"], Names(AccessRight.Read, PrivilegeDepth.None));
    }

    [Fact]
    public void Entity_options_count_roles_and_skip_misc_privileges()
    {
        var (index, _, _, _) = Build();
        var metadata = new Dictionary<string, EntityInfo>
        {
            ["account"] = new() { LogicalName = "account", DisplayName = "Khách hàng" },
        };

        var options = EntityRoleLookup.BuildEntityOptions(index, Catalog, metadata);

        Assert.Equal(["contact", "account"], options.Select(o => o.LogicalName));
        Assert.Equal("Khách hàng", options.Single(o => o.LogicalName == "account").DisplayName);
        Assert.Equal(2, options.Single(o => o.LogicalName == "account").RoleCount);
        Assert.Equal(2, options.Single(o => o.LogicalName == "contact").RoleCount);
    }
}
