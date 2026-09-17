using System.IO;
using ClosedXML.Excel;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class TeamAnalyzerTests
{
    private static PrivilegeDefinition Priv(string name, AccessRight right, string? entity) =>
        new() { Id = Guid.NewGuid(), Name = name, AccessRight = right, EntityLogicalName = entity, CanBeGlobal = true };

    private static readonly Dictionary<string, EntityInfo> Metadata = new(StringComparer.OrdinalIgnoreCase)
    {
        ["account"] = new() { LogicalName = "account", DisplayName = "Account" },
    };

    [Fact]
    public void Merge_takes_highest_depth_and_tracks_sources()
    {
        var read = Priv("prvReadAccount", AccessRight.Read, "account");
        var write = Priv("prvWriteAccount", AccessRight.Write, "account");
        var export = Priv("prvExportToExcel", AccessRight.None, null);

        var roleA = new Dictionary<Guid, PrivilegeDepth> { [read.Id] = PrivilegeDepth.User, [export.Id] = PrivilegeDepth.Organization };
        var roleB = new Dictionary<Guid, PrivilegeDepth> { [read.Id] = PrivilegeDepth.Organization, [write.Id] = PrivilegeDepth.BusinessUnit };

        var (entities, misc) = TeamAnalyzer.MergePrivileges([read, write, export], [("Role A", roleA), ("Role B", roleB)], Metadata);

        var account = Assert.Single(entities);
        Assert.Equal(PrivilegeDepth.Organization, account.Read.Depth);
        Assert.Equal(PrivilegeDepth.BusinessUnit, account.Write.Depth);
        Assert.Equal(["Role A (User)", "Role B (Organization)"], account.Read.SourceRoles);
        Assert.Equal("Role A, Role B", account.SourcesText);
        Assert.Contains("Từ role: Role A (User), Role B (Organization)", account.Read.ToolTip);

        var exportRow = Assert.Single(misc);
        Assert.Equal(PrivilegeDepth.Organization, exportRow.Depth);
        Assert.Equal("Role A (Organization)", exportRow.SourcesText);
    }

    [Fact]
    public void Owner_team_without_roles_is_flagged()
    {
        var analysis = new TeamAnalysis { Team = new TeamInfo { Name = "T", TeamType = 0 } };
        var finding = Assert.Single(TeamAnalyzer.BuildFindings(analysis));
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
        Assert.Contains("Owner team", finding.Title);
    }

    [Fact]
    public void Entra_and_default_teams_cannot_manage_members()
    {
        Assert.False(new TeamInfo { TeamType = 2 }.CanManageMembers);
        Assert.False(new TeamInfo { TeamType = 0, IsDefault = true }.CanManageMembers);
        Assert.True(new TeamInfo { TeamType = 1 }.CanManageMembers);

        var analysis = new TeamAnalysis
        {
            Team = new TeamInfo { Name = "SG", TeamType = 2 },
            Roles = [new TeamRoleAssignment { Name = "R" }],
        };
        var findings = TeamAnalyzer.BuildFindings(analysis).ToList();
        Assert.Contains(findings, f => f.Title.Contains("Entra ID"));
        Assert.DoesNotContain(findings, f => f.Title.Contains("chưa có thành viên"));
    }

    [Fact]
    public void Demo_team_findings_include_privilege_risks()
    {
        var (roles, _) = DemoData.Create();
        var (_, analysis) = DemoData.CreateTeams(roles);

        Assert.Contains(analysis.Findings, f => f.Title.Contains("disabled"));
        Assert.Contains(analysis.Findings, f => f.Title.Contains("prvExportToExcel") && f.Detail.Contains("3 thành viên"));
    }

    [Fact]
    public void Exports_team_workbook()
    {
        var (roles, _) = DemoData.Create();
        var (_, analysis) = DemoData.CreateTeams(roles);
        var path = Path.Combine(Path.GetTempPath(), $"sra_team_{Guid.NewGuid():N}.xlsx");
        try
        {
            ExcelExporter.ExportTeamAnalysis(analysis, path);

            using var workbook = new XLWorkbook(path);
            Assert.Equal(
                ["Tong quan", "Security Roles", "Thanh vien", "Quyen hieu luc", "Quyen khac", "Apps"],
                workbook.Worksheets.Select(w => w.Name));
            Assert.Equal(analysis.Members.Count + 1, workbook.Worksheet("Thanh vien").LastRowUsed()!.RowNumber());
        }
        finally
        {
            File.Delete(path);
        }
    }
}
