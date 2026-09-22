using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class FormRoleAnalyzerTests
{
    private static readonly Guid SalesRoleId = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SalesCopyId = new("11111111-1111-1111-1111-1111111111aa");
    private static readonly Guid ServiceRoleId = new("22222222-2222-2222-2222-222222222222");
    private static readonly Guid DeletedRoleId = new("99999999-9999-9999-9999-999999999999");

    private static RoleDirectory Directory() => new()
    {
        Roots =
        [
            new SecurityRoleInfo { Id = SalesRoleId, Name = "Sales Manager", BusinessUnitName = "contoso" },
            new SecurityRoleInfo { Id = ServiceRoleId, Name = "Customer Service", BusinessUnitName = "contoso" },
        ],
        CopyToRoot = new Dictionary<Guid, Guid>
        {
            [SalesRoleId] = SalesRoleId,
            // Bản sao của Sales Manager ở business unit con.
            [SalesCopyId] = SalesRoleId,
            [ServiceRoleId] = ServiceRoleId,
        },
    };

    private static DataverseService.FormInfo Form(
        string name,
        int type = 2,
        bool everyone = false,
        bool unreadable = false,
        params Guid[] roleIds) =>
        new(Guid.NewGuid(), name, "lead", type, false, 1, [.. roleIds], everyone, unreadable);

    private static FormRoleRow Build(DataverseService.FormInfo form) =>
        FormRoleAnalyzer.Build([form], Directory()).Single();

    [Fact]
    public void Specific_roles_are_resolved_to_names()
    {
        var row = Build(Form("Lead", roleIds: [SalesRoleId, ServiceRoleId]));

        Assert.Equal(FormVisibility.SpecificRoles, row.Visibility);
        Assert.Equal(2, row.RoleCount);
        Assert.Contains("Customer Service", row.RolesText);
        Assert.Contains("Sales Manager", row.RolesText);
        Assert.All(row.Roles, r => Assert.False(r.IsMissing));
    }

    [Fact]
    public void Business_unit_copies_resolve_to_the_root_role_and_are_listed_once()
    {
        var row = Build(Form("Lead", roleIds: [SalesRoleId, SalesCopyId]));

        var role = Assert.Single(row.Roles);
        Assert.Equal(SalesRoleId, role.RoleId);
        Assert.Equal("Sales Manager", role.RoleName);
    }

    [Fact]
    public void A_role_that_no_longer_exists_is_flagged_not_dropped()
    {
        var row = Build(Form("Lead", roleIds: [DeletedRoleId]));

        var role = Assert.Single(row.Roles);
        Assert.True(role.IsMissing);
        Assert.Equal("(role không còn tồn tại)", role.DisplayName);
        // Id vẫn hiện được để tra trong D365.
        Assert.Equal(DeletedRoleId.ToString(), role.BusinessUnitText);
    }

    [Fact]
    public void Everyone_is_reported_as_open_to_every_role()
    {
        var row = Build(Form("Lead", everyone: true));

        Assert.Equal(FormVisibility.Everyone, row.Visibility);
        Assert.True(row.IsOpenToEveryone);
        Assert.Contains("Mọi role", row.RolesText);
    }

    [Fact]
    public void Unreadable_display_conditions_are_not_treated_as_everyone()
    {
        var row = Build(Form("Lead", everyone: false, unreadable: true));

        Assert.Equal(FormVisibility.Unreadable, row.Visibility);
        Assert.False(row.IsOpenToEveryone);
        Assert.Contains("Không đọc được", row.VisibilityText);
    }

    [Theory]
    [InlineData(6)]  // Quick View
    [InlineData(7)]  // Quick Create
    public void Quick_forms_cannot_be_scoped_to_roles(int formType)
    {
        Assert.False(FormRoleAnalyzer.IsRoleScoped(formType));
        Assert.Equal(FormVisibility.NotRoleScoped, Build(Form("Quick", formType)).Visibility);
    }

    [Theory]
    [InlineData(0)]   // Dashboard
    [InlineData(2)]   // Main
    [InlineData(10)]  // Interactive Dashboard
    [InlineData(12)]  // Main - Interactive
    [InlineData(103)] // Power BI Dashboard
    public void Role_scoped_form_types_match_the_component_analysis(int formType) =>
        Assert.True(FormRoleAnalyzer.IsRoleScoped(formType));

    [Fact]
    public void Specific_roles_with_an_empty_list_warns_that_only_admins_see_the_form()
    {
        var row = Build(Form("Lead"));

        Assert.Equal(FormVisibility.SpecificRoles, row.Visibility);
        Assert.Contains("System Administrator", row.RolesText);
    }

    [Fact]
    public void Has_role_matches_through_a_business_unit_copy()
    {
        var row = Build(Form("Lead", roleIds: [SalesCopyId]));

        Assert.True(row.HasRole(SalesRoleId));
        Assert.False(row.HasRole(ServiceRoleId));
    }

    [Fact]
    public void Dashboards_have_no_entity()
    {
        var dashboard = new DataverseService.FormInfo(
            Guid.NewGuid(), "Sales Dashboard", "none", 0, false, 1, [SalesRoleId], false);

        var row = FormRoleAnalyzer.Build([dashboard], Directory()).Single();

        Assert.Equal("", row.EntityLogicalName);
        Assert.Equal("—", row.EntityText);
        Assert.Equal("Dashboard", row.FormTypeText);
    }

    [Fact]
    public void Entity_display_name_comes_from_metadata_when_available()
    {
        var metadata = new Dictionary<string, EntityInfo>(StringComparer.OrdinalIgnoreCase)
        {
            ["lead"] = new EntityInfo { LogicalName = "lead", DisplayName = "Khách hàng tiềm năng" },
        };

        var row = FormRoleAnalyzer.Build([Form("Lead")], Directory(), metadata).Single();

        Assert.Equal("Khách hàng tiềm năng", row.EntityDisplayName);
        Assert.Equal("lead", row.EntityLogicalName);
    }

    [Fact]
    public void Rows_are_sorted_by_entity_then_form_name()
    {
        var forms = new List<DataverseService.FormInfo>
        {
            new(Guid.NewGuid(), "Zebra", "account", 2, false, 1, [], true),
            new(Guid.NewGuid(), "Alpha", "account", 2, false, 1, [], true),
            new(Guid.NewGuid(), "Beta", "aaccount", 2, false, 1, [], true),
        };

        var names = FormRoleAnalyzer.Build(forms, Directory()).Select(r => r.FormName).ToList();

        Assert.Equal(["Beta", "Alpha", "Zebra"], names);
    }
}

/// <summary>Ghi role vào DisplayConditions phải đọc lại được đúng như trước và không đụng phần còn lại của form.</summary>
public class FormXmlRoleWritingTests
{
    private static readonly Guid RoleA = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid RoleB = new("22222222-2222-2222-2222-222222222222");

    private const string Tabs = """<tabs><tab name="general"><labels><label description="General" languagecode="1033" /></labels></tab></tabs>""";

    private static (HashSet<Guid> RoleIds, bool Everyone) Parse(string xml)
    {
        Assert.True(DataverseService.TryParseFormXmlRoles(xml, out var result));
        return result;
    }

    [Fact]
    public void Replacing_roles_keeps_attributes_and_the_rest_of_the_form()
    {
        var xml = $"""<form>{Tabs}<DisplayConditions Order="3" FallbackForm="false"><Role Id="{RoleA:B}" /></DisplayConditions></form>""";

        var written = DataverseService.ReplaceFormXmlRoles(xml, [RoleA, RoleB]);

        Assert.Equal([RoleA, RoleB], Parse(written).RoleIds.OrderBy(id => id));
        Assert.Contains("""Order="3" """.TrimEnd(), written);
        Assert.Contains("""FallbackForm="false" """.TrimEnd(), written);
        Assert.Contains(Tabs, written);
    }

    [Fact]
    public void Empty_list_is_written_as_everyone()
    {
        var xml = $"""<form><DisplayConditions Order="0" FallbackForm="true"><Role Id="{RoleA:B}" /></DisplayConditions>{Tabs}</form>""";

        var written = DataverseService.ReplaceFormXmlRoles(xml, []);

        var (ids, everyone) = Parse(written);
        Assert.Empty(ids);
        Assert.True(everyone);
        Assert.Contains("<Everyone />", written);
    }

    [Fact]
    public void Form_without_display_conditions_gets_a_new_node()
    {
        var written = DataverseService.ReplaceFormXmlRoles($"<form>{Tabs}</form>", [RoleB]);

        var (ids, everyone) = Parse(written);
        Assert.Equal([RoleB], ids);
        Assert.False(everyone);
        Assert.Contains(Tabs, written);
    }
}
