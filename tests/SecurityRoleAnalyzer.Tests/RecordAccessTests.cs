using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class RecordReferenceParsingTests
{
    private static readonly Guid Id = new("3fa85f64-5717-4562-b3fc-2c963f66afa6");

    [Fact]
    public void Parses_a_d365_record_url()
    {
        var result = RecordAccessExplainer.ParseRecordReference(
            $"https://contoso.crm5.dynamics.com/main.aspx?pagetype=entityrecord&etn=account&id={Id}");

        Assert.Equal(("account", Id), result);
    }

    [Fact]
    public void Parses_url_with_parameters_in_any_order()
    {
        var result = RecordAccessExplainer.ParseRecordReference(
            $"https://contoso.crm5.dynamics.com/main.aspx?id={Id}&etn=new_loan&pagetype=entityrecord");

        Assert.Equal(("new_loan", Id), result);
    }

    [Fact]
    public void Parses_plain_entity_and_id()
    {
        Assert.Equal(("account", Id), RecordAccessExplainer.ParseRecordReference($"account {Id}"));
        Assert.Equal(("account", Id), RecordAccessExplainer.ParseRecordReference($"account/{Id}"));
        Assert.Equal(("account", Id), RecordAccessExplainer.ParseRecordReference($"account,{{{Id}}}"));
    }

    [Fact]
    public void Returns_null_for_text_without_a_record()
    {
        Assert.Null(RecordAccessExplainer.ParseRecordReference(""));
        Assert.Null(RecordAccessExplainer.ParseRecordReference("account"));
        Assert.Null(RecordAccessExplainer.ParseRecordReference("https://contoso.crm5.dynamics.com/main.aspx?etn=account"));
        Assert.Null(RecordAccessExplainer.ParseRecordReference("không phải bản ghi"));
    }
}

public class AccessTeamTemplateTests
{
    [Fact]
    public void Decodes_the_dataverse_access_rights_mask()
    {
        // Read + Write + Append + AppendTo = 1 + 2 + 4 + 16
        Assert.Equal("Read, Write, Append, AppendTo", AccessTeamTemplateInfo.AccessRightsText(23));
        Assert.Equal("Read", AccessTeamTemplateInfo.AccessRightsText(1));
        Assert.Equal("(không có quyền)", AccessTeamTemplateInfo.AccessRightsText(0));
    }

    [Fact]
    public void Delete_share_and_assign_use_the_high_bits()
    {
        Assert.Equal("Delete", AccessTeamTemplateInfo.AccessRightsText(65536));
        Assert.Equal("Share", AccessTeamTemplateInfo.AccessRightsText(262144));
        Assert.Equal("Assign", AccessTeamTemplateInfo.AccessRightsText(524288));
    }

    [Fact]
    public void Entity_text_falls_back_to_the_type_code()
    {
        var template = new AccessTeamTemplateInfo { Name = "Sales access", EntityTypeCode = 1234 };
        Assert.Contains("1234", template.EntityText);

        template.EntityDisplayName = "Khoản vay";
        template.EntityLogicalName = "new_loan";
        Assert.Equal("Khoản vay (new_loan)", template.EntityText);
    }
}

public class HierarchySecurityTests
{
    [Fact]
    public void Disabled_hierarchy_says_so()
    {
        Assert.Contains("đang tắt", new HierarchySecurityInfo { IsEnabled = false }.Text);
    }

    [Fact]
    public void Enabled_hierarchy_names_the_model_and_depth()
    {
        var manager = new HierarchySecurityInfo { IsEnabled = true, UsesPositions = false, Depth = 3 };
        Assert.Contains("manager hierarchy", manager.Text);
        Assert.Contains("3 cấp", manager.Text);

        var position = new HierarchySecurityInfo { IsEnabled = true, UsesPositions = true, Depth = 2 };
        Assert.Contains("position hierarchy", position.Text);
    }

    [Fact]
    public void Unreadable_configuration_is_reported_not_assumed_off()
    {
        Assert.Contains("Không đọc được", new HierarchySecurityInfo { IsReadable = false }.Text);
    }
}

public class RecordAccessExplanationTests
{
    private static RecordAccessExplanation Explanation(params AccessRight[] rights) => new()
    {
        User = new UserInfo { FullName = "Nguyễn Văn An" },
        Record = new RecordOwnerInfo { EntityDisplayName = "Khách hàng", RecordName = "Contoso" },
        EffectiveRights = rights,
    };

    [Fact]
    public void Headline_reflects_read_access()
    {
        Assert.Contains("ĐỌC ĐƯỢC", Explanation(AccessRight.Read).Headline);
        Assert.Contains("KHÔNG đọc được", Explanation().Headline);
    }

    [Fact]
    public void Rights_text_lists_every_granted_right()
    {
        var text = Explanation(AccessRight.Read, AccessRight.Write).RightsText;
        Assert.Contains("Read", text);
        Assert.Contains("Write", text);
    }

    [Fact]
    public void Organization_owned_record_explains_it_has_no_owner()
    {
        var record = new RecordOwnerInfo { IsOrganizationOwned = true, EntityDisplayName = "Đơn vị tiền tệ" };
        Assert.Contains("sở hữu tổ chức", record.OwnerText);
    }

    [Fact]
    public void Owner_text_names_the_team_when_a_team_owns_the_record()
    {
        var record = new RecordOwnerInfo { OwnerIsTeam = true, OwnerName = "Sales Team", OwningBusinessUnitName = "contoso" };
        Assert.StartsWith("Team: Sales Team", record.OwnerText);
        Assert.Contains("contoso", record.OwnerText);
    }
}
