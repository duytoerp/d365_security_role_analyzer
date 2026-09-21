using System.IO;
using ClosedXML.Excel;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

/// <summary>
/// Role của form nằm trong node DisplayConditions bên trong formxml – Dataverse không có
/// bảng hay cột riêng cho thông tin này.
/// </summary>
public class FormXmlRoleParsingTests
{
    private static (HashSet<Guid> RoleIds, bool Everyone) Parse(string? xml)
    {
        Assert.True(DataverseService.TryParseFormXmlRoles(xml, out var result), "XML phải đọc được");
        return result;
    }

    /// <summary>formxml thật: DisplayConditions là con của form, nằm cạnh tabs.</summary>
    private static string FormXml(string displayConditions) => $"""
        <form>
          <tabs><tab name="general"><labels><label description="General" languagecode="1033" /></labels></tab></tabs>
          {displayConditions}
        </form>
        """;

    [Fact]
    public void Empty_form_xml_means_everyone()
    {
        var (ids, everyone) = Parse(null);
        Assert.Empty(ids);
        Assert.True(everyone);
    }

    [Fact]
    public void A_form_without_display_conditions_is_open_to_everyone()
    {
        var (ids, everyone) = Parse(FormXml(""));
        Assert.Empty(ids);
        Assert.True(everyone);
    }

    [Fact]
    public void An_empty_display_conditions_node_is_open_to_everyone()
    {
        Assert.True(Parse(FormXml("<DisplayConditions Order=\"0\" FallbackForm=\"true\" />")).Everyone);
        Assert.True(Parse(FormXml("<DisplayConditions Order=\"0\"></DisplayConditions>")).Everyone);
    }

    [Fact]
    public void Parses_role_ids_with_braces_and_mixed_case()
    {
        var id1 = Guid.NewGuid();
        var id2 = Guid.NewGuid();
        // Dataverse ghi Id dạng {GUID} viết hoa.
        var braced = "{" + id1.ToString().ToUpperInvariant() + "}";
        var xml = FormXml($"""
            <DisplayConditions Order="0" FallbackForm="true">
              <Role Id="{braced}" />
              <Role Id="{id2}" />
            </DisplayConditions>
            """);

        var (ids, everyone) = Parse(xml);

        Assert.False(everyone);
        Assert.Equal(2, ids.Count);
        Assert.Contains(id1, ids);
        Assert.Contains(id2, ids);
    }

    [Fact]
    public void Role_elements_outside_display_conditions_are_ignored()
    {
        // formxml có nhiều node tên "role" cho mục đích khác – chỉ node trong DisplayConditions mới tính.
        var assigned = Guid.NewGuid();
        var xml = FormXml($"""
            <Role Id="{Guid.NewGuid()}" />
            <DisplayConditions Order="0"><Role Id="{assigned}" /></DisplayConditions>
            <Role Id="{Guid.NewGuid()}" />
            """);

        var ids = Parse(xml).RoleIds;

        Assert.Equal([assigned], ids);
    }

    [Fact]
    public void Invalid_xml_is_reported_unreadable_instead_of_everyone()
    {
        // Suy ra "mọi role đều thấy" từ XML hỏng là sai theo hướng nguy hiểm.
        Assert.False(DataverseService.TryParseFormXmlRoles("<form><DisplayConditions><Role", out var result));
        Assert.False(result.Everyone);
        Assert.Empty(result.RoleIds);
    }
}

public class RoleAnalyzerTests
{
    private static PrivilegeDefinition Priv(string name, AccessRight right, string? entity) =>
        new() { Id = Guid.NewGuid(), Name = name, AccessRight = right, EntityLogicalName = entity, CanBeGlobal = true };

    [Fact]
    public void Builds_entity_matrix_and_misc_rows()
    {
        var readAccount = Priv("prvReadAccount", AccessRight.Read, "account");
        var deleteAccount = Priv("prvDeleteAccount", AccessRight.Delete, "account");
        var readContact = Priv("prvReadContact", AccessRight.Read, "contact");
        var export = Priv("prvExportToExcel", AccessRight.None, null);
        var weird = Priv("prvSpecialAccount", AccessRight.None, "account");

        var granted = new Dictionary<Guid, PrivilegeDepth>
        {
            [readAccount.Id] = PrivilegeDepth.Organization,
            [deleteAccount.Id] = PrivilegeDepth.User,
            [export.Id] = PrivilegeDepth.Organization,
        };
        var metadata = new Dictionary<string, EntityInfo>(StringComparer.OrdinalIgnoreCase)
        {
            ["account"] = new() { LogicalName = "account", DisplayName = "Account" },
        };

        var (entities, misc) = RoleAnalyzer.BuildPrivilegeRows([readAccount, deleteAccount, readContact, export, weird], granted, metadata);

        var account = Assert.Single(entities, e => e.LogicalName == "account");
        Assert.Equal("Account", account.DisplayName);
        Assert.Equal(PrivilegeDepth.Organization, account.Read.Depth);
        Assert.Equal(PrivilegeDepth.User, account.Delete.Depth);
        Assert.False(account.Create.Exists);
        Assert.Equal(2, account.GrantedCount);

        var contact = Assert.Single(entities, e => e.LogicalName == "contact");
        Assert.True(contact.Read.Exists);
        Assert.False(contact.HasAnyPrivilege);
        Assert.Equal("contact", contact.DisplayName);

        Assert.Equal(2, misc.Count);
        Assert.True(misc.Single(m => m.Name == "prvExportToExcel").IsGranted);
        Assert.Equal("account", misc.Single(m => m.Name == "prvSpecialAccount").Entity);
    }

    [Fact]
    public void Findings_flag_sensitive_privileges_and_disabled_users()
    {
        var (_, analysis) = DemoData.Create();

        Assert.Contains(analysis.Findings, f => f.Severity == FindingSeverity.High && f.Title.Contains("entity nhạy cảm"));
        Assert.Contains(analysis.Findings, f => f.Title.Contains("prvBulkDelete"));
        Assert.Contains(analysis.Findings, f => f.Title.Contains("disabled"));
        Assert.Contains(analysis.Findings, f => f.Title.Contains("Delete mức Organization"));
        Assert.DoesNotContain(analysis.Findings, f => f.Title.Contains("prvActOnBehalfOfAnotherUser"));
    }

    [Theory]
    [InlineData(0, PrivilegeDepth.None)]
    [InlineData(1, PrivilegeDepth.User)]
    [InlineData(2, PrivilegeDepth.BusinessUnit)]
    [InlineData(4, PrivilegeDepth.ParentChild)]
    [InlineData(8, PrivilegeDepth.Organization)]
    [InlineData(12, PrivilegeDepth.Organization)]
    public void Depth_mask_maps_to_highest_depth(int mask, PrivilegeDepth expected) =>
        Assert.Equal(expected, EnumText.FromMask(mask));

    [Fact]
    public void Diff_status_text()
    {
        Assert.Equal("Chỉ có ở Role A", new PrivilegeDiffRow { DepthA = PrivilegeDepth.User }.Status);
        Assert.Equal("Chỉ có ở Role B", new PrivilegeDiffRow { DepthB = PrivilegeDepth.User }.Status);
        Assert.Equal("Role A rộng hơn", new PrivilegeDiffRow { DepthA = PrivilegeDepth.Organization, DepthB = PrivilegeDepth.User }.Status);
        Assert.Equal("Giống nhau", new PrivilegeDiffRow { DepthA = PrivilegeDepth.User, DepthB = PrivilegeDepth.User }.Status);
    }
}

public class ConnectionProfileTests
{
    [Fact]
    public void OAuth_connection_string_uses_defaults()
    {
        var cs = new ConnectionProfile { Url = "https://org.crm5.dynamics.com" }.BuildConnectionString(null, null);
        Assert.Contains("AuthType=OAuth", cs);
        Assert.Contains("Url=https://org.crm5.dynamics.com", cs);
        Assert.Contains($"AppId={ConnectionProfile.DefaultAppId}", cs);
    }

    [Fact]
    public void Client_secret_requires_secret()
    {
        var profile = new ConnectionProfile { Url = "https://org.crm.dynamics.com", AuthType = ConnectionAuthType.ClientSecret, ClientId = "abc" };
        Assert.Throws<ArgumentException>(() => profile.BuildConnectionString("", null));
        Assert.Contains("ClientSecret=s3cret", profile.BuildConnectionString("s3cret", null));
    }
}

public class ExcelExportTests
{
    [Fact]
    public void Exports_all_sheets()
    {
        var (_, analysis) = DemoData.Create();
        var path = Path.Combine(Path.GetTempPath(), $"sra_test_{Guid.NewGuid():N}.xlsx");
        try
        {
            ExcelExporter.ExportRoleAnalysis(analysis, path);

            using var workbook = new XLWorkbook(path);
            Assert.Equal(
                ["Tong quan", "Quyen Entity", "Quyen khac", "Users", "Teams", "Users qua Team", "Components"],
                workbook.Worksheets.Select(w => w.Name));
            var entitySheet = workbook.Worksheet("Quyen Entity");
            Assert.Equal("Entity", entitySheet.Cell(1, 1).GetString());
            Assert.Equal(analysis.EntityRows.Count(r => r.HasAnyPrivilege) + 1, entitySheet.LastRowUsed()!.RowNumber());
        }
        finally
        {
            File.Delete(path);
        }
    }
}
