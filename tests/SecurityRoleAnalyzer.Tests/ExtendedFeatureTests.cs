using System.IO;
using System.Windows;
using System.Windows.Controls;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.ViewModels;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.Tests;

public class PrivilegeEditingTests
{
    private static readonly PrivilegeDefinition NoDeep = new()
    {
        Id = Guid.NewGuid(), Name = "prvReadX", AccessRight = AccessRight.Read, EntityLogicalName = "x",
        CanBeBasic = true, CanBeLocal = true, CanBeDeep = false, CanBeGlobal = true,
    };

    [Fact]
    public void Cycle_skips_unsupported_depths_and_wraps()
    {
        Assert.Equal(PrivilegeDepth.User, NoDeep.Cycle(PrivilegeDepth.None, backward: false));
        Assert.Equal(PrivilegeDepth.Organization, NoDeep.Cycle(PrivilegeDepth.BusinessUnit, backward: false));
        Assert.Equal(PrivilegeDepth.None, NoDeep.Cycle(PrivilegeDepth.Organization, backward: false));
        Assert.Equal(PrivilegeDepth.Organization, NoDeep.Cycle(PrivilegeDepth.None, backward: true));
    }

    [Fact]
    public void Clamp_uses_highest_allowed_not_above_request()
    {
        Assert.Equal(PrivilegeDepth.BusinessUnit, NoDeep.Clamp(PrivilegeDepth.ParentChild));
        Assert.Equal(PrivilegeDepth.Organization, NoDeep.Clamp(PrivilegeDepth.Organization));
    }

    [Fact]
    public void Replacing_cell_marks_row_changed_and_raises_notification()
    {
        var (entities, _) = RoleAnalyzer.BuildPrivilegeRows([NoDeep], new Dictionary<Guid, PrivilegeDepth>(), new Dictionary<string, EntityInfo>());
        var row = Assert.Single(entities);
        var raised = new List<string?>();
        row.PropertyChanged += (_, e) => raised.Add(e.PropertyName);

        row.Replace(AccessRight.Read, row.Read.WithDepth(PrivilegeDepth.Organization));

        Assert.True(row.Read.IsChanged);
        Assert.True(row.HasChanges);
        Assert.Contains("Read", raised);
        row.Replace(AccessRight.Read, row.Read.WithDepth(row.Read.OriginalDepth));
        Assert.False(row.HasChanges);
    }
}

public class AccessIndexToolTests
{
    private static (List<SecurityRoleInfo> Roles, DemoData.Extended Data) Demo()
    {
        var (roles, _) = DemoData.Create();
        var (teams, teamAnalysis) = DemoData.CreateTeams(roles);
        return (roles, DemoData.CreateExtended(roles, teams, teamAnalysis));
    }

    [Fact]
    public void Effective_roles_include_team_roles()
    {
        var (_, data) = Demo();
        var binh = data.Index.Users.Single(u => u.FullName == "Trần Thị Bình");
        var effective = data.Index.EffectiveRolesOf(binh.Id).ToList();
        Assert.Contains(effective, e => e.TeamId is null);
        Assert.Contains(effective, e => e.TeamId is not null);
    }

    [Fact]
    public void Lookup_finds_users_via_direct_and_team_roles()
    {
        var (roles, data) = Demo();
        var privilege = new PrivilegeDefinition { Id = Guid.NewGuid(), Name = "prvReadLoan", AccessRight = AccessRight.Read, EntityLogicalName = "loan", CanBeGlobal = true };
        var officer = roles.First(r => r.Name.Contains("Loan Officer"));
        data.Index.RolePrivileges[officer.Id] = new() { [privilege.Id] = PrivilegeDepth.Organization };

        var (foundRoles, teams, users) = AccessLookup.Find(data.Index, privilege, PrivilegeDepth.BusinessUnit);

        Assert.Equal(officer.Id, Assert.Single(foundRoles).RoleId);
        Assert.Equal(2, teams.Count);
        Assert.Contains(users, u => u.Name == "Hoàng Gia Hân" && u.Via.Contains("team"));
        Assert.Contains(users, u => u.Name == "Đặng Thu Trang");
        Assert.All(users, u => Assert.Equal(PrivilegeDepth.Organization, u.Depth));

        var none = AccessLookup.Find(data.Index, privilege, PrivilegeDepth.Organization);
        Assert.Single(none.Roles);
    }

    [Fact]
    public void Access_review_flags_users_and_unused_roles()
    {
        var (_, data) = Demo();
        var (users, roles) = AccessReviewBuilder.Build(data.Index);

        Assert.Contains(users, u => u.User.FullName == "Phạm Quốc Dũng" && u.Flags.Contains("Không có role"));
        Assert.Contains(users, u => u.User.FullName == "Võ Thanh Khoa" && u.Flags.Contains("Disabled còn role"));
        Assert.Contains(users, u => u.User.FullName == "Trần Thị Bình" && u.Flags.Contains("Role trùng"));
        Assert.Contains(roles, r => r.Role.Name == "Customer Service Representative" && r.IsUnused);
    }

    [Fact]
    public void Business_unit_tree_and_scope()
    {
        var (_, data) = Demo();
        var root = Assert.Single(BusinessUnitAnalyzer.BuildTree(data.Index));
        Assert.Equal(3, root.Children.Count);
        var hcm = root.Children.Single(c => c.Unit.Name == "Hồ Chí Minh");
        Assert.Single(hcm.Children);

        var analysis = BusinessUnitAnalyzer.Analyze(hcm, data.Index);
        Assert.Contains("2 BU", analysis.ScopeText);
        Assert.Contains(analysis.RoleUsage, r => r.TeamUserCount > 0);
    }

    [Fact]
    public void App_analysis_counts_effective_users()
    {
        var (_, data) = Demo();
        Assert.Equal(2, data.AppAnalysis.Roles.Count);
        Assert.Contains(data.AppAnalysis.Users, u => u.Via.Contains("team"));
    }

    [Fact]
    public void Import_resolves_and_skips_existing_assignments()
    {
        var (roles, data) = Demo();
        var officer = roles.First(r => r.Name.Contains("Loan Officer"));
        List<ImportRow> rows =
        [
            new() { RowNumber = 2, PrincipalType = "User", Principal = "binh.tt@contoso.vn", Action = ImportActions.AssignRole, Target = officer.Name },
            new() { RowNumber = 3, PrincipalType = "User", Principal = "dung.pq@contoso.vn", Action = ImportActions.AssignRole, Target = "Salesperson" },
            new() { RowNumber = 4, PrincipalType = "User", Principal = "khong-ton-tai", Action = ImportActions.AssignRole, Target = "Salesperson" },
            new() { RowNumber = 5, PrincipalType = "Team", Principal = "Loan Officers - HCM", Action = ImportActions.AddToTeam, Target = "x" },
            new() { RowNumber = 6, PrincipalType = "User", Principal = "Phạm Quốc Dũng", Action = ImportActions.AddToTeam, Target = "Loan Officers - HCM" },
            new() { RowNumber = 7, PrincipalType = "User", Principal = "an.nv@contoso.vn", Action = ImportActions.AddToTeam, Target = "contoso" },
            new() { RowNumber = 8, PrincipalType = "User", Principal = "an.nv@contoso.vn", Action = "Xóa", Target = "Salesperson" },
        ];

        ImportService.Resolve(rows, data.Index);

        Assert.Equal(ImportStatus.Skipped, rows[0].Status);
        Assert.Equal(ImportStatus.Valid, rows[1].Status);
        Assert.Equal(ImportStatus.Error, rows[2].Status);
        Assert.Equal(ImportStatus.Error, rows[3].Status);
        Assert.Equal(ImportStatus.Valid, rows[4].Status);
        Assert.Equal(ImportStatus.Error, rows[5].Status); // default team
        Assert.Equal(ImportStatus.Error, rows[6].Status);
    }

    [Fact]
    public void Import_template_round_trip_and_csv()
    {
        var xlsx = Path.Combine(Path.GetTempPath(), $"sra_import_{Guid.NewGuid():N}.xlsx");
        var csv = Path.Combine(Path.GetTempPath(), $"sra_import_{Guid.NewGuid():N}.csv");
        try
        {
            ImportService.CreateTemplate(xlsx);
            var rows = ImportService.Read(xlsx);
            Assert.Equal(5, rows.Count);
            Assert.Equal("user1@contoso.com", rows[0].Principal);

            File.WriteAllLines(csv, ["Loại,Principal,Hành động,Đối tượng", "User,\"Nguyễn, An\",Gán role,Salesperson"]);
            var csvRow = Assert.Single(ImportService.Read(csv));
            Assert.Equal("Nguyễn, An", csvRow.Principal);
            Assert.Equal("Salesperson", csvRow.Target);
        }
        finally
        {
            File.Delete(xlsx);
            File.Delete(csv);
        }
    }

    [Fact]
    public void Snapshot_compare_detects_changes()
    {
        var (roles, data) = Demo();
        var catalog = new List<PrivilegeDefinition> { new() { Id = Guid.NewGuid(), Name = "prvReadAccount", AccessRight = AccessRight.Read, EntityLogicalName = "account" } };
        var officer = roles.First(r => r.Name.Contains("Loan Officer"));
        data.Index.RolePrivileges[officer.Id] = new() { [catalog[0].Id] = PrivilegeDepth.User };
        var before = SnapshotService.Create(data.Index, catalog, "dev", "tester");

        var path = Path.Combine(Path.GetTempPath(), $"sra_snap_{Guid.NewGuid():N}.json");
        SnapshotService.Save(before, path);
        var reloaded = SnapshotService.Load(path);
        File.Delete(path);

        var copyPath = WriteAndReturn(reloaded);
        var after = SnapshotService.Load(copyPath);
        File.Delete(copyPath);
        after.Roles.Single(r => r.Name == officer.Name).Privileges["prvReadAccount"] = PrivilegeDepth.Organization;
        after.Roles.RemoveAll(r => r.Name == "System Customizer");
        after.UserRoles.Add(new SnapshotLink { Principal = "new.user@contoso.vn", PrincipalName = "New", Target = "Salesperson" });

        var diff = SnapshotService.Compare(reloaded, after);

        Assert.Contains(diff, d => d.Category == SnapshotService.CategoryPrivilege && d.ChangeType == SnapshotService.Changed && d.After == "Organization");
        Assert.Contains(diff, d => d.Category == SnapshotService.CategoryRole && d.ChangeType == SnapshotService.Removed && d.Item == "System Customizer");
        Assert.Contains(diff, d => d.Category == SnapshotService.CategoryUserRole && d.ChangeType == SnapshotService.Added);
        Assert.DoesNotContain(diff, d => d.Category == SnapshotService.CategoryTeamMember);
    }

    private static string WriteAndReturn(EnvironmentSnapshot snapshot)
    {
        var path = Path.Combine(Path.GetTempPath(), $"sra_snap_{Guid.NewGuid():N}.json");
        SnapshotService.Save(snapshot, path);
        return path;
    }

    [Fact]
    public void User_findings_detect_duplicates_and_missing_roles()
    {
        var (_, data) = Demo();
        Assert.Contains(data.UserAnalysis.Findings, f => f.Title.Contains("nhiều nguồn"));

        var empty = new UserAnalysis { User = new UserInfo { FullName = "X" } };
        Assert.Contains(UserAnalyzer.BuildFindings(empty), f => f.Severity == FindingSeverity.High);
    }

    [Fact]
    public void Connection_profile_secret_is_encrypted()
    {
        var profile = new ConnectionProfile { Url = "https://x.crm.dynamics.com", AuthType = ConnectionAuthType.ClientSecret, ClientId = "c" };
        profile.SetSecret("p@ss");
        Assert.DoesNotContain("p@ss", profile.EncryptedSecret);
        Assert.Equal("p@ss", profile.GetSecret());
        Assert.True(profile.CanQuickConnect);
    }
}

/// <summary>Tạo mọi cửa sổ/view với dữ liệu demo để phát hiện lỗi XAML (resource thiếu, binding sai kiểu...).</summary>
public class XamlSmokeTests
{
    // WPF chỉ cho một Application trên một thread: mọi test giao diện chạy trên cùng một thread STA.
    private static readonly Lazy<System.Windows.Threading.Dispatcher> UiDispatcher = new(() =>
    {
        System.Windows.Threading.Dispatcher? dispatcher = null;
        using var ready = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
            ready.Set();
            System.Windows.Threading.Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        ready.Wait();
        return dispatcher!;
    });

    internal static void EnsureApp()
    {
        if (Application.Current is not null)
            return;
        var app = new App { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.InitializeComponent();
    }

    internal static void RunSta(Action action)
    {
        Exception? error = null;
        UiDispatcher.Value.Invoke(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                error = ex;
            }
        });
        if (error is not null)
            throw new Exception("XAML smoke test failed", error);
    }

    [Fact]
    public void Clicking_depth_cell_in_edit_mode_changes_privilege()
    {
        RunSta(() =>
        {
            EnsureApp();

            var main = new MainViewModel();
            main.LoadDemo();
            main.ToggleEditPrivilegesCommand.Execute(null);
            Assert.True(main.IsEditingPrivileges);

            var grid = new DataGrid { ItemsSource = main.EntityRowsView, DataContext = main };
            grid.Columns.Add(new SecurityRoleAnalyzer.Controls.DepthColumn { Header = "Read", CellPath = "Read" });
            var window = new Window { Content = grid, Width = 400, Height = 300, Left = -10000, ShowActivated = false, WindowStartupLocation = WindowStartupLocation.Manual };
            window.Show();
            window.UpdateLayout();

            var cell = FindChild<DataGridCell>(grid) ?? throw new InvalidOperationException("Không tìm thấy ô");
            var border = FindChild<Border>(cell, b => b.DataContext is EntityPrivilegeRow && b.Child is TextBlock) ?? throw new InvalidOperationException("Không tìm thấy border");
            var row = (EntityPrivilegeRow)border.DataContext;
            var before = row.Read.Depth;

            border.RaiseEvent(new System.Windows.Input.MouseButtonEventArgs(System.Windows.Input.Mouse.PrimaryDevice, 0, System.Windows.Input.MouseButton.Left)
            {
                RoutedEvent = UIElement.MouseLeftButtonUpEvent,
            });

            Assert.NotEqual(before, row.Read.Depth);
            Assert.Equal(1, main.PendingChangeCount);

            main.DiscardPrivilegesCommand.Execute(null);
            Assert.Equal(before, row.Read.Depth);
            Assert.Equal(0, main.PendingChangeCount);
            window.Close();
        });
    }

    private static T? FindChild<T>(DependencyObject parent, Func<T, bool>? predicate = null) where T : DependencyObject
    {
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);
            if (child is T match && (predicate is null || predicate(match)))
                return match;
            if (FindChild(child, predicate) is { } nested)
                return nested;
        }
        return null;
    }

    [Fact]
    public void All_windows_and_views_load()
    {
        RunSta(() =>
        {
            EnsureApp();

            var main = new MainViewModel();
            main.LoadDemo();

            var windows = new List<Window>
            {
                new LookupWindow { DataContext = new LookupViewModel(main) },
                new AccessReviewWindow { DataContext = new AccessReviewViewModel(main) },
                new BulkPrivilegeWindow { DataContext = new BulkPrivilegeViewModel(main) },
                new SnapshotWindow { DataContext = new SnapshotViewModel(main) },
                new ImportWindow { DataContext = new ImportViewModel(main) },
                new HistoryWindow { DataContext = new HistoryViewModel(main) },
                new RoleOverlapWindow { DataContext = new RoleOverlapViewModel(main) },
                new AuditWindow { DataContext = new AuditViewModel(main) },
                new RecordAccessWindow { DataContext = new RecordAccessViewModel(main) },
                new FormRoleWindow { DataContext = new FormRoleViewModel(main) },
                new Window { Content = new UsersView { DataContext = main.UserManager } },
                new Window { Content = new AppsView { DataContext = main.AppManager } },
                new Window { Content = new FieldSecurityView { DataContext = main.FieldSecurity } },
                new Window { Content = new BusinessUnitsView { DataContext = main.BusinessUnits } },
                new Window { Content = new TeamsView { DataContext = main.TeamManager } },
            };

            foreach (var window in windows)
            {
                window.WindowStartupLocation = WindowStartupLocation.Manual;
                window.Left = -10000;
                window.ShowActivated = false;
                window.Show();
                window.UpdateLayout();
                window.Close();
            }
        });
    }
}
