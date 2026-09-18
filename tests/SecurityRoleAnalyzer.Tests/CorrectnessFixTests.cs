using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class RoleTemplateTests
{
    [Fact]
    public void System_administrator_is_detected_by_template_regardless_of_name()
    {
        var renamed = new SecurityRoleInfo { Name = "Quản trị toàn hệ thống", RoleTemplateId = RoleTemplates.SystemAdministrator };
        Assert.True(renamed.IsSystemAdministrator);
    }

    [Fact]
    public void Custom_role_named_like_admin_still_matches_as_fallback()
    {
        Assert.True(new SecurityRoleInfo { Name = "System Administrator" }.IsSystemAdministrator);
        Assert.False(new SecurityRoleInfo { Name = "Sales Manager" }.IsSystemAdministrator);
    }

    [Fact]
    public void Other_system_role_is_not_administrator()
    {
        var customizer = new SecurityRoleInfo { Name = "System Customizer", RoleTemplateId = RoleTemplates.SystemCustomizer };
        Assert.False(customizer.IsSystemAdministrator);
    }
}

public class TeamPrivilegeInheritanceTests
{
    private static readonly PrivilegeDefinition ReadAccount = new()
    {
        Id = Guid.NewGuid(), Name = "prvReadAccount", AccessRight = AccessRight.Read, EntityLogicalName = "account",
        CanBeBasic = true, CanBeLocal = true, CanBeDeep = true, CanBeGlobal = true,
    };

    [Fact]
    public void Team_scoped_role_is_marked_in_privilege_source()
    {
        var privileges = new Dictionary<Guid, PrivilegeDepth> { [ReadAccount.Id] = PrivilegeDepth.User };
        var (entities, _) = TeamAnalyzer.MergePrivileges(
            [ReadAccount],
            [("Sales", privileges, false)],
            new Dictionary<string, EntityInfo>());

        var row = Assert.Single(entities);
        Assert.Contains("chỉ record của team", row.Read.ToolTip);
    }

    [Fact]
    public void Normal_role_has_no_team_scope_note()
    {
        var privileges = new Dictionary<Guid, PrivilegeDepth> { [ReadAccount.Id] = PrivilegeDepth.User };
        var (entities, _) = TeamAnalyzer.MergePrivileges(
            [ReadAccount],
            [("Sales", privileges)],
            new Dictionary<string, EntityInfo>());

        Assert.DoesNotContain("chỉ record của team", Assert.Single(entities).Read.ToolTip);
    }

    [Fact]
    public void Role_via_team_reports_team_scope_in_source_text()
    {
        var viaTeam = new UserRoleAssignment { Name = "Sales", IsDirect = false, TeamName = "Sales Team", IsInherited = false };
        Assert.True(viaTeam.IsTeamScopedOnly);
        Assert.Contains("chỉ record của team", viaTeam.SourceText);

        var direct = new UserRoleAssignment { Name = "Sales", IsDirect = true };
        Assert.False(direct.IsTeamScopedOnly);
    }
}

public class ActionLogUndoTests
{
    private static ActionLogEntry Entry(bool success, bool partial) => new()
    {
        Action = "Sửa privilege",
        Success = success,
        PartiallyApplied = partial,
        Undo = new UndoInfo { Kind = UndoKind.RestorePrivilegeBackup, BackupFile = "x.json" },
    };

    [Fact]
    public void Successful_action_can_be_undone()
    {
        Assert.True(Entry(success: true, partial: false).CanUndo);
    }

    [Fact]
    public void Failed_action_that_changed_data_can_still_be_undone()
    {
        var entry = Entry(success: false, partial: true);
        Assert.True(entry.CanUndo);
        Assert.Contains("dở dang", entry.ResultText);
    }

    [Fact]
    public void Failed_action_that_changed_nothing_is_not_undoable()
    {
        Assert.False(Entry(success: false, partial: false).CanUndo);
    }

    [Fact]
    public void Already_undone_action_cannot_be_undone_again()
    {
        var entry = Entry(success: true, partial: false);
        entry.IsUndone = true;
        Assert.False(entry.CanUndo);
    }
}
