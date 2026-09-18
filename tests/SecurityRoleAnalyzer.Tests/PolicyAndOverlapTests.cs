using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class SecurityPolicyTests
{
    [Fact]
    public void Default_policy_flags_known_sensitive_entities()
    {
        var policy = new SecurityPolicy();
        Assert.True(policy.IsSensitiveEntity("systemuser"));
        Assert.True(policy.IsSensitiveEntity("SYSTEMUSER"));
        Assert.False(policy.IsSensitiveEntity("account"));
    }

    [Fact]
    public void Bypass_and_delete_privileges_are_high_severity()
    {
        var policy = new SecurityPolicy();
        Assert.Equal(FindingSeverity.High, policy.SeverityOf("prvBypassCustomPlugins"));
        Assert.Equal(FindingSeverity.High, policy.SeverityOf("prvDeleteAuditPartitions"));
        Assert.Equal(FindingSeverity.High, policy.SeverityOf("prvActOnBehalfOfAnotherUser"));
        Assert.Equal(FindingSeverity.Medium, policy.SeverityOf("prvExportToExcel"));
    }

    [Fact]
    public void Custom_thresholds_change_which_findings_appear()
    {
        var read = new PrivilegeDefinition
        {
            Id = Guid.NewGuid(), Name = "prvWriteAccount", AccessRight = AccessRight.Write, EntityLogicalName = "account",
            CanBeBasic = true, CanBeLocal = true, CanBeDeep = true, CanBeGlobal = true,
        };
        var (rows, _) = RoleAnalyzer.BuildPrivilegeRows(
            [read],
            new Dictionary<Guid, PrivilegeDepth> { [read.Id] = PrivilegeDepth.Organization },
            new Dictionary<string, EntityInfo>());

        // Mặc định cần hơn 50 entity mới cảnh báo, nên một entity thì chưa có gì.
        Assert.DoesNotContain(RoleAnalyzer.BuildPrivilegeFindings(rows, [], new SecurityPolicy()),
            f => f.Title.Contains("Write mức Organization"));

        var strict = new SecurityPolicy { OrgWriteThreshold = 0 };
        Assert.Contains(RoleAnalyzer.BuildPrivilegeFindings(rows, [], strict),
            f => f.Title.Contains("Write mức Organization"));
    }

    [Fact]
    public void Custom_sensitive_entity_list_is_honoured()
    {
        var write = new PrivilegeDefinition
        {
            Id = Guid.NewGuid(), Name = "prvWriteLoan", AccessRight = AccessRight.Write, EntityLogicalName = "new_loan",
            CanBeBasic = true, CanBeLocal = true, CanBeDeep = true, CanBeGlobal = true,
        };
        var (rows, _) = RoleAnalyzer.BuildPrivilegeRows(
            [write],
            new Dictionary<Guid, PrivilegeDepth> { [write.Id] = PrivilegeDepth.User },
            new Dictionary<string, EntityInfo>());

        var policy = new SecurityPolicy { SensitiveEntities = ["new_loan"] };
        Assert.Contains(RoleAnalyzer.BuildPrivilegeFindings(rows, [], policy),
            f => f.Title.Contains("entity nhạy cảm"));
    }
}

public class RoleOverlapTests
{
    private static AccessIndex Index(params (string Name, Guid[] Privileges)[] roles)
    {
        var index = new AccessIndex();
        foreach (var (name, privileges) in roles)
        {
            var id = Guid.NewGuid();
            index.Roles.Add(new SecurityRoleInfo { Id = id, Name = name });
            index.RolePrivileges[id] = privileges.ToDictionary(p => p, _ => PrivilegeDepth.User);
        }
        return index;
    }

    private static readonly Guid P1 = Guid.NewGuid();
    private static readonly Guid P2 = Guid.NewGuid();
    private static readonly Guid P3 = Guid.NewGuid();
    private static readonly Guid P4 = Guid.NewGuid();

    [Fact]
    public void Identical_roles_are_reported_as_fully_overlapping()
    {
        var rows = RoleOverlapAnalyzer.Find(Index(("A", [P1, P2]), ("B", [P1, P2])), 0.9);

        var row = Assert.Single(rows);
        Assert.Equal(1.0, row.Similarity);
        Assert.True(row.IsSubset);
        Assert.Contains("giống hệt", row.Suggestion);
    }

    [Fact]
    public void Subset_role_is_detected_and_named_in_the_suggestion()
    {
        var rows = RoleOverlapAnalyzer.Find(Index(("Lớn", [P1, P2, P3]), ("Nhỏ", [P1, P2])), 0.5);

        var row = Assert.Single(rows);
        Assert.True(row.IsSubset);
        Assert.Equal(0, row.OnlyInB);
        Assert.Contains("Nhỏ", row.Suggestion);
        Assert.Contains("Lớn", row.Suggestion);
    }

    [Fact]
    public void Unrelated_roles_are_below_the_threshold()
    {
        Assert.Empty(RoleOverlapAnalyzer.Find(Index(("A", [P1, P2]), ("B", [P3, P4])), 0.5));
    }

    [Fact]
    public void Roles_without_privileges_are_ignored()
    {
        Assert.Empty(RoleOverlapAnalyzer.Find(Index(("A", []), ("B", [])), 0.1));
    }

    [Fact]
    public void Similarity_is_jaccard_so_partial_overlap_scores_between_zero_and_one()
    {
        // Chung 2, riêng mỗi bên 1 → 2 / 4 = 0.5
        var rows = RoleOverlapAnalyzer.Find(Index(("A", [P1, P2, P3]), ("B", [P1, P2, P4])), 0.4);

        var row = Assert.Single(rows);
        Assert.Equal(0.5, row.Similarity, 3);
        Assert.False(row.IsSubset);
    }
}
