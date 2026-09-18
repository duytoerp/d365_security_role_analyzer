using System.Collections;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.ViewModels;

/// <summary>Chế độ Model-driven App: role được thêm vào app và user truy cập được.</summary>
public sealed partial class AppManagerViewModel(MainViewModel host) : ObservableObject
{
    private bool _suppressLoad;

    public bool IsLoaded { get; private set; }

    public ObservableCollection<AppModuleInfo> Apps { get; } = [];

    [ObservableProperty] private string _appSearchText = "";
    [ObservableProperty] private AppModuleInfo? _selectedApp;

    public ICollectionView AppsView => field ??= CreateAppsView();

    private ICollectionView CreateAppsView()
    {
        var view = CollectionViewSource.GetDefaultView(Apps);
        view.Filter = o => o is AppModuleInfo a && (MainViewModel.Contains(a.Name, AppSearchText) || MainViewModel.Contains(a.UniqueName, AppSearchText));
        return view;
    }

    partial void OnAppSearchTextChanged(string value) => AppsView.Refresh();

    public async Task LoadListAsync()
    {
        if (host.Service is not { } service)
            return;
        var apps = await service.GetAppModulesAsync();
        Apps.Clear();
        foreach (var app in apps)
            Apps.Add(app);
        IsLoaded = true;
    }

    public void Clear()
    {
        IsLoaded = false;
        Analysis = null;
        _suppressLoad = true;
        SelectedApp = null;
        _suppressLoad = false;
        Apps.Clear();
        OnPropertyChanged(string.Empty);
    }

    partial void OnSelectedAppChanged(AppModuleInfo? value)
    {
        if (value is not null && !_suppressLoad)
            _ = LoadAppAsync(value);
    }

    [RelayCommand]
    private Task ReloadAsync() => SelectedApp is null ? Task.CompletedTask : LoadAppAsync(SelectedApp);

    private async Task LoadAppAsync(AppModuleInfo app)
    {
        if (host.Service is not { } service)
            return;

        await host.RunBusyAsync($"Đang phân tích app \"{app.Name}\"...", async () =>
        {
            var index = await service.GetAccessIndexAsync(new Progress<string>(t => host.BusyText = t));
            var links = await service.GetAppRoleLinksAsync();
            var analysis = AppAnalyzer.Analyze(app, links, index);
            app.RoleCount = analysis.Roles.Count;
            Apply(analysis);
            host.StatusText = $"App \"{app.Name}\": {analysis.Roles.Count} role, {analysis.Users.Count} user truy cập được.";
        });
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAnalysis))]
    [NotifyCanExecuteChangedFor(nameof(AddRolesCommand), nameof(ExportCommand))]
    private AppAnalysis? _analysis;

    public bool HasAnalysis => Analysis is not null;
    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];
    public ICollectionView? RolesView { get; private set; }
    public ICollectionView? UsersView { get; private set; }

    [ObservableProperty] private string _userSearchText = "";
    partial void OnUserSearchTextChanged(string value) => UsersView?.Refresh();

    public string RolesTabHeader => Analysis is null ? "Security Roles" : $"Security Roles ({Analysis.Roles.Count})";
    public string UsersTabHeader => Analysis is null ? "User truy cập" : $"User truy cập ({Analysis.Users.Count})";
    public string FindingsHeader => Analysis is null ? "" : $"Phát hiện ({Analysis.Findings.Count})";
    public string Subtitle => Analysis?.App is not { } a ? "" : $"{a.UniqueName}  ·  {a.ManagedText}  ·  {a.StateText}  ·  Id: {a.Id}";

    private void Apply(AppAnalysis analysis)
    {
        RolesView = new ListCollectionView(analysis.Roles);
        UsersView = new ListCollectionView(analysis.Users)
        {
            Filter = o => o is PrincipalAccessRow u && (MainViewModel.Contains(u.Name, UserSearchText) || MainViewModel.Contains(u.Via, UserSearchText) || MainViewModel.Contains(u.BusinessUnitName, UserSearchText)),
        };
        SummaryCards.Clear();
        SummaryCards.Add(new SummaryCard("Security Role", analysis.Roles.Count.ToString(), "role được thêm vào app"));
        SummaryCards.Add(new SummaryCard("User truy cập", analysis.Users.Count(u => !u.IsDisabled).ToString(), $"{analysis.Users.Count(u => u.IsDisabled)} user disabled"));
        SummaryCards.Add(new SummaryCard("Qua team", analysis.Users.Count(u => u.Via.Contains("(team ")).ToString(), "user nhận role qua team"));
        Analysis = analysis;
        OnPropertyChanged(string.Empty);
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedRolesText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveRolesCommand))]
    private IList? _selectedRoles;

    private List<AppRoleRow> PickedRoles => SelectedRoles?.OfType<AppRoleRow>().ToList() ?? [];
    public string SelectedRolesText => PickedRoles.Count == 0 ? "" : $"Đã chọn {PickedRoles.Count} role";
    private bool CanRemoveRoles => PickedRoles.Count > 0;

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task AddRolesAsync()
    {
        if (host.Service is not { } service || Analysis is not { } analysis)
            return;

        var assigned = analysis.Roles.Select(r => r.RoleId).ToHashSet();
        var available = host.Roles.Where(r => !assigned.Contains(r.Id)).ToList();
        var picked = PrincipalPickerWindow.Show(App.Current.MainWindow, $"Thêm role vào app \"{analysis.App.Name}\"",
            text => Task.FromResult(available.Where(r => MainViewModel.Contains(r.Name, text))
                .Select(r => new PrincipalSearchResult { Id = r.Id, Name = r.Name, Detail = r.ManagedText, BusinessUnitName = r.BusinessUnitName }).ToList()),
            actionText: "Thêm vào app", hint: "User có role được chọn sẽ mở được app.", searchOnOpen: true);
        if (picked is null || picked.Count == 0)
            return;

        await host.RunBusyAsync("Đang thêm role vào app...", () =>
            service.AssociateAppRolesAsync(analysis.App.Id, analysis.App.Name, picked.Select(p => (p.Id, p.Name)).ToList()));
        await LoadAppAsync(analysis.App);
    }

    [RelayCommand(CanExecute = nameof(CanRemoveRoles))]
    private async Task RemoveRolesAsync()
    {
        if (host.Service is not { } service || Analysis is not { } analysis)
            return;
        var roles = PickedRoles;
        if (!Dialogs.Confirm($"Gỡ {roles.Count} role khỏi app \"{analysis.App.Name}\"?\n\n" + string.Join("\n", roles.Select(r => $"• {r.Name} ({r.EffectiveUserCount} user)"))))
            return;

        await host.RunBusyAsync("Đang gỡ role khỏi app...", () =>
            service.DisassociateAppRolesAsync(analysis.App.Id, analysis.App.Name, roles.Select(r => (r.RoleId, r.Name)).ToList()));
        await LoadAppAsync(analysis.App);
    }

    [RelayCommand]
    private void OpenRole(AppRoleRow? role)
    {
        if (role is not null)
            host.OpenRole(role.RoleId);
    }

    [RelayCommand]
    private void OpenUser(PrincipalAccessRow? user)
    {
        if (user is not null)
            _ = host.OpenUserAsync(user.Id);
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void Export()
    {
        if (Analysis is not { } a)
            return;
        host.ExportWorkbook($"App_{MainViewModel.SafeFileName(a.App.Name)}", wb =>
        {
            ExcelExporter.AddInfoSheet(wb, "Tong quan", [("App", a.App.Name), ("Unique name", a.App.UniqueName), ("Managed", a.App.ManagedText)], a.Findings);
            ExcelExporter.AddSheet(wb, "Security Roles", a.Roles,
                new ExportColumn<AppRoleRow>("Role", r => r.Name),
                new ExportColumn<AppRoleRow>("User trực tiếp", r => r.DirectUserCount),
                new ExportColumn<AppRoleRow>("Team", r => r.TeamCount),
                new ExportColumn<AppRoleRow>("User hiệu lực", r => r.EffectiveUserCount));
            ExcelExporter.AddPrincipalSheet(wb, "User truy cap", a.Users);
        });
    }

    public void LoadDemo(List<AppModuleInfo> apps, AppAnalysis analysis)
    {
        Apps.Clear();
        foreach (var app in apps)
            Apps.Add(app);
        IsLoaded = true;
        _suppressLoad = true;
        SelectedApp = apps.First(a => a.Id == analysis.App.Id);
        _suppressLoad = false;
        Apply(analysis);
    }
}

/// <summary>Chế độ Field Security Profile.</summary>
public sealed partial class FieldSecurityViewModel(MainViewModel host) : ObservableObject
{
    private bool _suppressLoad;

    public bool IsLoaded { get; private set; }
    public ObservableCollection<FieldSecurityProfileInfo> Profiles { get; } = [];

    [ObservableProperty] private string _profileSearchText = "";
    [ObservableProperty] private FieldSecurityProfileInfo? _selectedProfile;

    public ICollectionView ProfilesView => field ??= CreateView();

    private ICollectionView CreateView()
    {
        var view = CollectionViewSource.GetDefaultView(Profiles);
        view.Filter = o => o is FieldSecurityProfileInfo p && MainViewModel.Contains(p.Name, ProfileSearchText);
        return view;
    }

    partial void OnProfileSearchTextChanged(string value) => ProfilesView.Refresh();

    public async Task LoadListAsync()
    {
        if (host.Service is not { } service)
            return;
        var profiles = await service.GetFieldSecurityProfilesAsync();
        Profiles.Clear();
        foreach (var profile in profiles)
            Profiles.Add(profile);
        IsLoaded = true;
    }

    public void Clear()
    {
        IsLoaded = false;
        Analysis = null;
        _suppressLoad = true;
        SelectedProfile = null;
        _suppressLoad = false;
        Profiles.Clear();
        OnPropertyChanged(string.Empty);
    }

    partial void OnSelectedProfileChanged(FieldSecurityProfileInfo? value)
    {
        if (value is not null && !_suppressLoad)
            _ = LoadProfileAsync(value);
    }

    [RelayCommand]
    private Task ReloadAsync() => SelectedProfile is null ? Task.CompletedTask : LoadProfileAsync(SelectedProfile);

    private async Task LoadProfileAsync(FieldSecurityProfileInfo profile)
    {
        if (host.Service is not { } service)
            return;
        await host.RunBusyAsync($"Đang phân tích profile \"{profile.Name}\"...", async () =>
        {
            var analysis = await FieldProfileAnalyzer.AnalyzeAsync(service, profile, CancellationToken.None);
            Apply(analysis);
            host.StatusText = $"Profile \"{profile.Name}\": {analysis.Permissions.Count} cột, {analysis.EffectiveUsers.Count} user hiệu lực.";
        });
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAnalysis))]
    [NotifyCanExecuteChangedFor(nameof(AddUsersCommand), nameof(AddTeamsCommand), nameof(ExportCommand))]
    private FieldProfileAnalysis? _analysis;

    public bool HasAnalysis => Analysis is not null;
    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];
    public ICollectionView? PermissionsView { get; private set; }
    public ICollectionView? UsersView { get; private set; }
    public ICollectionView? TeamsView { get; private set; }
    public ICollectionView? EffectiveView { get; private set; }

    [ObservableProperty] private string _permissionSearchText = "";
    partial void OnPermissionSearchTextChanged(string value) => PermissionsView?.Refresh();

    [ObservableProperty] private string _userSearchText = "";
    partial void OnUserSearchTextChanged(string value) => UsersView?.Refresh();

    [ObservableProperty] private string _teamSearchText = "";
    partial void OnTeamSearchTextChanged(string value) => TeamsView?.Refresh();

    [ObservableProperty] private string _effectiveSearchText = "";
    partial void OnEffectiveSearchTextChanged(string value) => EffectiveView?.Refresh();

    public string PermissionsTabHeader => Analysis is null ? "Field permissions" : $"Field permissions ({Analysis.Permissions.Count})";
    public string UsersTabHeader => Analysis is null ? "Users" : $"Users ({Analysis.Users.Count})";
    public string TeamsTabHeader => Analysis is null ? "Teams" : $"Teams ({Analysis.Teams.Count})";
    public string EffectiveTabHeader => Analysis is null ? "User hiệu lực" : $"User hiệu lực ({Analysis.EffectiveUsers.Count})";
    public string FindingsHeader => Analysis is null ? "" : $"Phát hiện ({Analysis.Findings.Count})";
    public string Subtitle => Analysis?.Profile is not { } p ? "" : $"{p.ManagedText}  ·  Id: {p.Id}" + (string.IsNullOrEmpty(p.Description) ? "" : $"  ·  {p.Description}");

    private void Apply(FieldProfileAnalysis analysis)
    {
        PermissionsView = new ListCollectionView(analysis.Permissions)
        {
            Filter = o => o is FieldPermissionRow r && (MainViewModel.Contains(r.EntityDisplayName, PermissionSearchText)
                || MainViewModel.Contains(r.AttributeDisplayName, PermissionSearchText) || MainViewModel.Contains(r.Attribute, PermissionSearchText)),
        };
        UsersView = new ListCollectionView(analysis.Users)
        {
            Filter = o => o is UserInfo u && (MainViewModel.Contains(u.FullName, UserSearchText)
                || MainViewModel.Contains(u.DomainName, UserSearchText) || MainViewModel.Contains(u.BusinessUnitName, UserSearchText)),
        };
        TeamsView = new ListCollectionView(analysis.Teams)
        {
            Filter = o => o is TeamInfo t && (MainViewModel.Contains(t.Name, TeamSearchText)
                || MainViewModel.Contains(t.BusinessUnitName, TeamSearchText) || MainViewModel.Contains(t.TeamTypeText, TeamSearchText)),
        };
        EffectiveView = new ListCollectionView(analysis.EffectiveUsers)
        {
            Filter = o => o is PrincipalAccessRow r && (MainViewModel.Contains(r.Name, EffectiveSearchText)
                || MainViewModel.Contains(r.Detail, EffectiveSearchText) || MainViewModel.Contains(r.Via, EffectiveSearchText)),
        };
        SummaryCards.Clear();
        SummaryCards.Add(new SummaryCard("Cột bảo mật", analysis.Permissions.Count.ToString(), $"{analysis.Permissions.Select(p => p.Entity).Distinct().Count()} entity"));
        SummaryCards.Add(new SummaryCard("User trực tiếp", analysis.Users.Count.ToString(), "gán trực tiếp"));
        SummaryCards.Add(new SummaryCard("Team", analysis.Teams.Count.ToString(), "gán qua team"));
        SummaryCards.Add(new SummaryCard("User hiệu lực", analysis.EffectiveUsers.Count.ToString(), "trực tiếp + thành viên team"));
        Analysis = analysis;
        OnPropertyChanged(string.Empty);
    }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveUsersCommand))]
    private IList? _selectedUsers;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveTeamsCommand))]
    private IList? _selectedTeams;

    private List<UserInfo> PickedUsers => SelectedUsers?.OfType<UserInfo>().ToList() ?? [];
    private List<TeamInfo> PickedTeams => SelectedTeams?.OfType<TeamInfo>().ToList() ?? [];
    private bool CanRemoveUsers => PickedUsers.Count > 0;
    private bool CanRemoveTeams => PickedTeams.Count > 0;

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private Task AddUsersAsync() => AddAsync(isTeam: false);

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private Task AddTeamsAsync() => AddAsync(isTeam: true);

    private async Task AddAsync(bool isTeam)
    {
        if (host.Service is not { } service || Analysis is not { } analysis)
            return;
        var existing = isTeam ? analysis.Teams.Select(t => t.Id).ToHashSet() : analysis.Users.Select(u => u.Id).ToHashSet();
        var picked = PrincipalPickerWindow.Show(App.Current.MainWindow,
            $"Thêm {(isTeam ? "team" : "user")} vào profile \"{analysis.Profile.Name}\"",
            async (text, top) => (isTeam ? await service.SearchTeamsAsync(text, top) : await service.SearchUsersAsync(text, top)).Where(p => !existing.Contains(p.Id)).ToList(),
            actionText: "Thêm vào profile");
        if (picked is null || picked.Count == 0)
            return;

        await host.RunBusyAsync("Đang cập nhật profile...", () =>
            service.AssociateFieldProfileAsync(analysis.Profile.Id, analysis.Profile.Name, isTeam, picked.Select(p => (p.Id, p.Name)).ToList()));
        await LoadProfileAsync(analysis.Profile);
    }

    [RelayCommand(CanExecute = nameof(CanRemoveUsers))]
    private Task RemoveUsersAsync() => RemoveAsync(false, PickedUsers.Select(u => (u.Id, u.FullName)).ToList());

    [RelayCommand(CanExecute = nameof(CanRemoveTeams))]
    private Task RemoveTeamsAsync() => RemoveAsync(true, PickedTeams.Select(t => (t.Id, t.Name)).ToList());

    private async Task RemoveAsync(bool isTeam, List<(Guid Id, string Name)> items)
    {
        if (host.Service is not { } service || Analysis is not { } analysis || items.Count == 0)
            return;
        if (!Dialogs.Confirm($"Gỡ {items.Count} {(isTeam ? "team" : "user")} khỏi profile \"{analysis.Profile.Name}\"?\n\n" + string.Join("\n", items.Select(i => "• " + i.Name))))
            return;
        await host.RunBusyAsync("Đang cập nhật profile...", () =>
            service.DisassociateFieldProfileAsync(analysis.Profile.Id, analysis.Profile.Name, isTeam, items));
        await LoadProfileAsync(analysis.Profile);
    }

    [RelayCommand]
    private void OpenUser(object? item)
    {
        var id = item switch { UserInfo u => u.Id, PrincipalAccessRow p => p.Id, _ => Guid.Empty };
        if (id != Guid.Empty)
            _ = host.OpenUserAsync(id);
    }

    [RelayCommand]
    private void OpenTeam(TeamInfo? team)
    {
        if (team is not null)
            host.OpenTeam(team.Id);
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void Export()
    {
        if (Analysis is not { } a)
            return;
        host.ExportWorkbook($"FieldSecurity_{MainViewModel.SafeFileName(a.Profile.Name)}", wb =>
        {
            ExcelExporter.AddInfoSheet(wb, "Tong quan", [("Profile", a.Profile.Name), ("Mô tả", a.Profile.Description), ("Managed", a.Profile.ManagedText)], a.Findings);
            ExcelExporter.AddSheet(wb, "Field permissions", a.Permissions,
                new ExportColumn<FieldPermissionRow>("Entity", r => r.EntityDisplayName),
                new ExportColumn<FieldPermissionRow>("Cột", r => r.AttributeDisplayName),
                new ExportColumn<FieldPermissionRow>("Logical name", r => $"{r.Entity}.{r.Attribute}"),
                new ExportColumn<FieldPermissionRow>("Read", r => r.CanRead ? "Yes" : "No"),
                new ExportColumn<FieldPermissionRow>("Create", r => r.CanCreate ? "Yes" : "No"),
                new ExportColumn<FieldPermissionRow>("Update", r => r.CanUpdate ? "Yes" : "No"));
            ExcelExporter.AddPrincipalSheet(wb, "User hieu luc", a.EffectiveUsers);
        });
    }

    public void LoadDemo(List<FieldSecurityProfileInfo> profiles, FieldProfileAnalysis analysis)
    {
        Profiles.Clear();
        foreach (var p in profiles)
            Profiles.Add(p);
        IsLoaded = true;
        _suppressLoad = true;
        SelectedProfile = profiles.First(p => p.Id == analysis.Profile.Id);
        _suppressLoad = false;
        Apply(analysis);
    }
}

/// <summary>Chế độ sơ đồ Business Unit.</summary>
public sealed partial class BusinessUnitsViewModel(MainViewModel host) : ObservableObject
{
    private AccessIndex? _index;

    public bool IsLoaded { get; private set; }
    public ObservableCollection<BusinessUnitNode> Roots { get; } = [];

    [ObservableProperty] private BusinessUnitNode? _selectedNode;

    public async Task LoadListAsync()
    {
        if (host.Service is not { } service)
            return;
        _index = await service.GetAccessIndexAsync(new Progress<string>(t => host.BusyText = t));
        SetTree(BusinessUnitAnalyzer.BuildTree(_index));
        IsLoaded = true;
    }

    private void SetTree(IEnumerable<BusinessUnitNode> roots)
    {
        Roots.Clear();
        foreach (var root in roots)
            Roots.Add(root);
        OnPropertyChanged(nameof(TreeSummary));
    }

    public string TreeSummary => _index is null ? "" : $"{_index.BusinessUnits.Count} BU · {_index.Users.Count} user · {_index.Teams.Count} team";

    public void Clear()
    {
        IsLoaded = false;
        _index = null;
        Analysis = null;
        SelectedNode = null;
        Roots.Clear();
        OnPropertyChanged(string.Empty);
    }

    partial void OnSelectedNodeChanged(BusinessUnitNode? value)
    {
        if (value is null || _index is null)
            return;
        Apply(BusinessUnitAnalyzer.Analyze(value, _index));
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAnalysis))]
    [NotifyCanExecuteChangedFor(nameof(ExportCommand))]
    private BusinessUnitAnalysis? _analysis;

    public bool HasAnalysis => Analysis is not null;
    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];
    public ICollectionView? UsersView { get; private set; }
    public ICollectionView? TeamsView { get; private set; }
    public ICollectionView? RoleUsageView { get; private set; }

    [ObservableProperty] private string _userSearchText = "";
    partial void OnUserSearchTextChanged(string value) => UsersView?.Refresh();

    [ObservableProperty] private string _teamSearchText = "";
    partial void OnTeamSearchTextChanged(string value) => TeamsView?.Refresh();

    [ObservableProperty] private string _roleSearchText = "";
    partial void OnRoleSearchTextChanged(string value) => RoleUsageView?.Refresh();

    public string UsersTabHeader => Analysis is null ? "Users" : $"Users ({Analysis.Users.Count})";
    public string TeamsTabHeader => Analysis is null ? "Teams" : $"Teams ({Analysis.Teams.Count})";
    public string RolesTabHeader => Analysis is null ? "Role đang dùng" : $"Role đang dùng ({Analysis.RoleUsage.Count})";
    public string FindingsHeader => Analysis is null ? "" : $"Phát hiện ({Analysis.Findings.Count})";
    public string Subtitle => Analysis?.Node is not { } n ? "" : $"{n.Path}  ·  {n.Children.Count} BU con trực tiếp" + (n.Unit.IsDisabled ? "  ·  Disabled" : "") + $"  ·  Id: {n.Unit.Id}";

    private void Apply(BusinessUnitAnalysis analysis)
    {
        UsersView = new ListCollectionView(analysis.Users)
        {
            Filter = o => o is UserInfo u && (MainViewModel.Contains(u.FullName, UserSearchText) || MainViewModel.Contains(u.DomainName, UserSearchText)),
        };
        TeamsView = new ListCollectionView(analysis.Teams)
        {
            Filter = o => o is TeamInfo t && (MainViewModel.Contains(t.Name, TeamSearchText) || MainViewModel.Contains(t.TeamTypeText, TeamSearchText)),
        };
        RoleUsageView = new ListCollectionView(analysis.RoleUsage)
        {
            Filter = o => o is RoleUsageRow r && MainViewModel.Contains(r.Name, RoleSearchText),
        };
        var subtree = analysis.Node.DescendantsAndSelf().ToList();
        SummaryCards.Clear();
        SummaryCards.Add(new SummaryCard("User", analysis.Users.Count(u => !u.IsDisabled).ToString(), $"{analysis.Users.Count(u => u.IsDisabled)} disabled"));
        SummaryCards.Add(new SummaryCard("Team", analysis.Teams.Count.ToString(), "thuộc BU này"));
        SummaryCards.Add(new SummaryCard("BU con", (subtree.Count - 1).ToString(), $"{subtree.Sum(n => n.UserCount)} user trong cả nhánh"));
        SummaryCards.Add(new SummaryCard("Role đang dùng", analysis.RoleUsage.Count.ToString(), "bởi user của BU"));
        Analysis = analysis;
        OnPropertyChanged(string.Empty);
    }

    [RelayCommand]
    private void OpenUser(UserInfo? user)
    {
        if (user is not null)
            _ = host.OpenUserAsync(user.Id);
    }

    [RelayCommand]
    private void OpenTeam(TeamInfo? team)
    {
        if (team is not null)
            host.OpenTeam(team.Id);
    }

    [RelayCommand]
    private void OpenRole(RoleUsageRow? role)
    {
        if (role is not null)
            host.OpenRole(role.RoleId);
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void Export()
    {
        if (Analysis is not { } a)
            return;
        host.ExportWorkbook($"BU_{MainViewModel.SafeFileName(a.Node.Unit.Name)}", wb =>
        {
            ExcelExporter.AddInfoSheet(wb, "Tong quan", [("Business Unit", a.Node.Unit.Name), ("Đường dẫn", a.Node.Path), ("Phạm vi quyền", a.ScopeText)], a.Findings);
            ExcelExporter.AddUserSheet(wb, "Users", a.Users);
            ExcelExporter.AddSheet(wb, "Teams", a.Teams,
                new ExportColumn<TeamInfo>("Team", t => t.Name),
                new ExportColumn<TeamInfo>("Loại", t => t.TeamTypeText),
                new ExportColumn<TeamInfo>("Số role", t => t.RoleCount));
            ExcelExporter.AddSheet(wb, "Role dang dung", a.RoleUsage,
                new ExportColumn<RoleUsageRow>("Role", r => r.Name),
                new ExportColumn<RoleUsageRow>("User trực tiếp", r => r.DirectUserCount),
                new ExportColumn<RoleUsageRow>("User qua team", r => r.TeamUserCount),
                new ExportColumn<RoleUsageRow>("Tổng user", r => r.TotalUserCount));
        });
    }

    public void LoadDemo(AccessIndex index)
    {
        _index = index;
        SetTree(BusinessUnitAnalyzer.BuildTree(index));
        IsLoaded = true;
        SelectedNode = Roots.FirstOrDefault();
    }
}
