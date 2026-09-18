using System.IO;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class RoleDefinitionFileTests
{
    private static RoleDefinition Sample() => new()
    {
        Name = "Contoso - Loan Officer",
        SourceEnvironment = "dev.crm5.dynamics.com",
        BusinessUnitName = "contoso",
        IsInherited = false,
        Privileges =
        [
            new PrivilegeBackupItem { PrivilegeId = Guid.NewGuid(), Name = "prvReadAccount", Depth = PrivilegeDepth.BusinessUnit },
            new PrivilegeBackupItem { PrivilegeId = Guid.NewGuid(), Name = "prvWriteAccount", Depth = PrivilegeDepth.User },
        ],
        Apps = ["contoso_loanapp"],
    };

    [Fact]
    public void Round_trips_through_file()
    {
        var path = Path.Combine(Path.GetTempPath(), $"role_{Guid.NewGuid():N}.role.json");
        try
        {
            var original = Sample();
            RoleDefinitionService.Save(original, path);
            var loaded = RoleDefinitionService.Load(path);

            Assert.Equal(original.Name, loaded.Name);
            Assert.Equal(original.SourceEnvironment, loaded.SourceEnvironment);
            Assert.False(loaded.IsInherited);
            Assert.Equal(2, loaded.Privileges.Count);
            Assert.Equal(PrivilegeDepth.BusinessUnit, loaded.Privileges[0].Depth);
            Assert.Equal(["contoso_loanapp"], loaded.Apps);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Granted_count_ignores_none_depth()
    {
        var definition = Sample();
        definition.Privileges.Add(new PrivilegeBackupItem { Name = "prvDeleteAccount", Depth = PrivilegeDepth.None });
        Assert.Equal(2, definition.GrantedCount);
    }

    [Fact]
    public void Invalid_file_reports_clearly()
    {
        var path = Path.Combine(Path.GetTempPath(), $"role_{Guid.NewGuid():N}.json");
        File.WriteAllText(path, "null");
        try
        {
            Assert.Throws<InvalidDataException>(() => RoleDefinitionService.Load(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}

public class SnapshotApplyTests
{
    private static EnvironmentSnapshot Snapshot(string environment, params (string Role, (string Privilege, PrivilegeDepth Depth)[] Privileges)[] roles) => new()
    {
        Environment = environment,
        Roles = roles.Select(r => new SnapshotRole
        {
            Name = r.Role,
            Privileges = new SortedDictionary<string, PrivilegeDepth>(
                r.Privileges.ToDictionary(p => p.Privilege, p => p.Depth, StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase),
        }).ToList(),
    };

    [Fact]
    public void Privilege_rows_carry_target_depth_and_are_applicable()
    {
        var before = Snapshot("uat", ("Sales", [("prvReadAccount", PrivilegeDepth.User)]));
        var after = Snapshot("dev", ("Sales", [("prvReadAccount", PrivilegeDepth.Organization)]));

        var row = Assert.Single(SnapshotService.Compare(before, after), r => r.Category == SnapshotService.CategoryPrivilege);

        Assert.Equal(SnapshotService.Changed, row.ChangeType);
        Assert.Equal(PrivilegeDepth.Organization, row.TargetDepth);
        Assert.True(row.CanApply);
    }

    [Fact]
    public void Removed_privilege_targets_none_so_apply_revokes_it()
    {
        var before = Snapshot("uat", ("Sales", [("prvReadAccount", PrivilegeDepth.User)]));
        var after = Snapshot("dev", ("Sales", []));

        var row = Assert.Single(SnapshotService.Compare(before, after), r => r.Category == SnapshotService.CategoryPrivilege);

        Assert.Equal(SnapshotService.Removed, row.ChangeType);
        Assert.Equal(PrivilegeDepth.None, row.TargetDepth);
    }

    [Fact]
    public void New_role_row_is_applicable_so_the_role_can_be_created()
    {
        var before = Snapshot("uat");
        var after = Snapshot("dev", ("Sales", [("prvReadAccount", PrivilegeDepth.User)]));

        var row = Assert.Single(SnapshotService.Compare(before, after), r => r.Category == SnapshotService.CategoryRole);

        Assert.Equal(SnapshotService.Added, row.ChangeType);
        Assert.True(row.CanApply);
    }

    [Fact]
    public void Principal_assignment_rows_are_not_applicable()
    {
        var before = new EnvironmentSnapshot { Environment = "uat" };
        var after = new EnvironmentSnapshot
        {
            Environment = "dev",
            UserRoles = [new SnapshotLink { Principal = "an@contoso.com", PrincipalName = "An", Target = "Sales" }],
        };

        var row = Assert.Single(SnapshotService.Compare(before, after), r => r.Category == SnapshotService.CategoryUserRole);
        Assert.False(row.CanApply);
    }
}

public class RoleTemplateModelTests
{
    [Fact]
    public void Inheritance_text_describes_scope()
    {
        Assert.Equal("User + Team", new SecurityRoleInfo { IsInherited = true }.InheritanceText);
        Assert.Equal("Chỉ quyền Team", new SecurityRoleInfo { IsInherited = false }.InheritanceText);
    }

    [Fact]
    public void Import_result_summary_lists_what_was_skipped()
    {
        var result = new RoleImportResult
        {
            Created = true,
            PrivilegesApplied = 12,
            AppsLinked = 1,
            MissingPrivileges = ["prvReadCustomThing"],
        };

        Assert.Contains("Đã tạo role mới", result.Summary);
        Assert.Contains("12 privilege", result.Summary);
        Assert.Contains("1 privilege không có", result.Summary);
    }
}
