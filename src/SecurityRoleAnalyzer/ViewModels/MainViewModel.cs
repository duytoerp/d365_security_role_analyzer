using System.Collections;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.ViewModels;

public sealed record SummaryCard(string Title, string Value, string Caption);

public sealed record ComponentCategorySummary(string Category, int Total, int Direct);

public sealed partial class MainViewModel : ObservableObject
{
    public const string AllCategories = "Tất cả";

    private DataverseService? _service;
    private CancellationTokenSource? _roleLoadCts;

    public MainViewModel()
    {
        RolesView = CollectionViewSource.GetDefaultView(Roles);
        RolesView.Filter = FilterRole;
        TeamManager = new TeamManagerViewModel(this);
        UserManager = new UserManagerViewModel(this);
        AppManager = new AppManagerViewModel(this);
        FieldSecurity = new FieldSecurityViewModel(this);
        BusinessUnits = new BusinessUnitsViewModel(this);
        ReloadProfiles(null);
    }

    internal DataverseService? Service => _service;

    /// <summary>Chế độ quản lý theo team.</summary>
    public TeamManagerViewModel TeamManager { get; }

    #region Connection & busy state

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand), nameof(CompareCommand), nameof(OpenLookupCommand), nameof(OpenAccessReviewCommand),
        nameof(OpenBulkPrivilegesCommand), nameof(OpenImportCommand), nameof(RestoreBackupCommand))]
    private bool _isConnected;

    [ObservableProperty] private string _connectionText = "Chưa kết nối – nhấn \"Kết nối\" để bắt đầu";
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _busyText = "";
    [ObservableProperty] private string _statusText = "Sẵn sàng";

    [RelayCommand]
    private async Task ConnectAsync()
    {
        var result = ConnectionWindow.Show(App.Current.MainWindow);
        if (result is null)
            return;

        await ConnectWithAsync(result.Value.ConnectionString, result.Value.Profile);
    }

    [RelayCommand(CanExecute = nameof(IsConnected))]
    private async Task RefreshAsync()
    {
        if (_service is null)
            return;

        var selectedRoleId = SelectedRole?.Id;
        var selectedTeamId = TeamManager.SelectedTeam?.Id;
        var selectedUserId = UserManager.SelectedUser?.Id;
        await RunBusyAsync("Đang tải lại dữ liệu...", async () =>
        {
            _service.ClearCache(includeDisk: true);
            UserManager.Clear();
            AppManager.Clear();
            FieldSecurity.Clear();
            BusinessUnits.Clear();
            await LoadRolesAsync();
            await TeamManager.LoadTeamsAsync();
        });
        await EnsureModeLoadedAsync(Mode);

        // Chỉ phân tích lại mục đang xem ở chế độ hiện tại.
        switch (Mode)
        {
            case AppMode.Teams when selectedTeamId is { } teamId:
                TeamManager.SelectTeam(teamId);
                break;
            case AppMode.Users when selectedUserId is { } userId:
                await UserManager.SelectUserAsync(userId);
                break;
            case AppMode.Roles when Roles.FirstOrDefault(r => r.Id == selectedRoleId) is { } role:
                SelectedRole = role;
                break;
        }
    }

    private async Task LoadRolesAsync()
    {
        var roles = await _service!.GetRolesAsync();
        Roles.Clear();
        foreach (var role in roles)
            Roles.Add(role);
        OnPropertyChanged(nameof(RoleCountText));
        StatusText = $"Đã tải {roles.Count} security role.";
    }

    internal async Task RunBusyAsync(string text, Func<Task> action)
    {
        IsBusy = true;
        BusyText = text;
        try
        {
            await action();
        }
        catch (OperationCanceledException)
        {
            // Bỏ qua khi người dùng chọn role khác.
        }
        catch (Exception ex)
        {
            StatusText = "Lỗi: " + ex.Message;
            Dialogs.ShowError(ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    #endregion

    #region Roles

    public ObservableCollection<SecurityRoleInfo> Roles { get; } = [];
    public ICollectionView RolesView { get; }

    [ObservableProperty] private string _roleSearchText = "";
    [ObservableProperty] private bool _hideManagedRoles;
    [ObservableProperty] private SecurityRoleInfo? _selectedRole;

    public string RoleCountText => $"{RolesView.Cast<object>().Count()} / {Roles.Count} role";

    partial void OnRoleSearchTextChanged(string value) => RefreshRoles();
    partial void OnHideManagedRolesChanged(bool value) => RefreshRoles();

    private void RefreshRoles()
    {
        RolesView.Refresh();
        OnPropertyChanged(nameof(RoleCountText));
    }

    private bool FilterRole(object item) =>
        item is SecurityRoleInfo role
        && (!HideManagedRoles || !role.IsManaged)
        && Contains(role.Name, RoleSearchText);

    partial void OnSelectedRoleChanged(SecurityRoleInfo? value)
    {
        if (value is not null)
            _ = LoadRoleAsync(value);
    }

    [RelayCommand]
    private Task ReloadRoleAsync() => SelectedRole is null ? Task.CompletedTask : LoadRoleAsync(SelectedRole);

    private async Task LoadRoleAsync(SecurityRoleInfo role)
    {
        if (_service is null)
            return;

        _roleLoadCts?.Cancel();
        var cts = _roleLoadCts = new CancellationTokenSource();

        await RunBusyAsync($"Đang phân tích role \"{role.Name}\"...", async () =>
        {
            var progress = new Progress<string>(text => BusyText = text);
            var watch = Stopwatch.StartNew();
            var analysis = await new RoleAnalyzer(_service).AnalyzeAsync(role, progress, cts.Token);
            if (cts.IsCancellationRequested)
                return;

            ApplyAnalysis(analysis);
            StatusText = $"Phân tích \"{role.Name}\" xong trong {watch.Elapsed.TotalSeconds:0.0}s" +
                         (analysis.Warnings.Count > 0 ? $" – {analysis.Warnings.Count} cảnh báo (xem tab Tổng quan)" : "");
        });
    }

    #endregion

    #region Analysis result

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAnalysis))]
    [NotifyCanExecuteChangedFor(nameof(ExportCommand), nameof(AddUserCommand), nameof(AddTeamCommand), nameof(OpenInBrowserCommand), nameof(ToggleEditPrivilegesCommand), nameof(CopyRoleCommand))]
    private RoleAnalysis? _analysis;

    public bool HasAnalysis => Analysis is not null;

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];
    public ObservableCollection<ComponentCategorySummary> ComponentSummary { get; } = [];

    public ICollectionView? EntityRowsView { get; private set; }
    public ICollectionView? MiscView { get; private set; }
    public ICollectionView? UsersView { get; private set; }
    public ICollectionView? TeamsView { get; private set; }
    public ICollectionView? TeamUsersView { get; private set; }
    public ICollectionView? ComponentsView { get; private set; }

    public string EntityTabHeader => Analysis is null ? "Quyền Entity" : $"Quyền Entity ({Analysis.EntityRows.Count(r => r.HasAnyPrivilege)})";
    public string MiscTabHeader => Analysis is null ? "Quyền khác" : $"Quyền khác ({Analysis.MiscPrivileges.Count(m => m.IsGranted)})";
    public string UsersTabHeader => Analysis is null ? "Users" : $"Users ({Analysis.Users.Count})";
    public string TeamsTabHeader => Analysis is null ? "Teams" : $"Teams ({Analysis.Teams.Count})";
    public string TeamUsersTabHeader => Analysis is null ? "Users qua Team" : $"Users qua Team ({Analysis.TeamUsers.Count})";
    public string ComponentsTabHeader => Analysis is null ? "Components" : $"Components ({Analysis.Components.Count})";
    public string FindingsHeader => Analysis is null ? "" : $"Phát hiện & rủi ro ({Analysis.Findings.Count})";
    public string WarningsText => Analysis is null ? "" : string.Join(Environment.NewLine, Analysis.Warnings);
    public bool HasWarnings => Analysis?.Warnings.Count > 0;
    public string RoleSubtitle => Analysis is null
        ? ""
        : $"Business Unit: {Analysis.Role.BusinessUnitName}  ·  {Analysis.Role.ManagedText}  ·  Sửa lần cuối: {Analysis.Role.ModifiedOn:dd/MM/yyyy HH:mm}  ·  {Analysis.RoleCopies.Count} bản sao theo BU  ·  Id: {Analysis.Role.Id}";

    public IReadOnlyList<string> ComponentCategories { get; } = [AllCategories, .. ComponentCategory.All];

    private void ClearAnalysis()
    {
        Analysis = null;
        SummaryCards.Clear();
        ComponentSummary.Clear();
    }

    private void ApplyAnalysis(RoleAnalysis analysis)
    {
        IsEditingPrivileges = false;
        PendingChangeCount = 0;

        EntityRowsView = CreateView(analysis.EntityRows, FilterEntity);
        MiscView = CreateView(analysis.MiscPrivileges, FilterMisc);
        UsersView = CreateView(analysis.Users, FilterUser);
        TeamsView = CreateView(analysis.Teams, FilterTeam);
        TeamUsersView = CreateView(analysis.TeamUsers, FilterTeamUser);
        ComponentsView = CreateView(analysis.Components, FilterComponent);

        SummaryCards.Clear();
        var granted = analysis.EntityRows.Where(r => r.HasAnyPrivilege).ToList();
        SummaryCards.Add(new SummaryCard("Entity có quyền", granted.Count.ToString(), $"trên tổng {analysis.EntityRows.Count} entity"));
        SummaryCards.Add(new SummaryCard("Entity custom", granted.Count(r => r.IsCustom).ToString(), "entity tùy chỉnh có quyền"));
        SummaryCards.Add(new SummaryCard("Quyền khác", analysis.MiscPrivileges.Count(m => m.IsGranted).ToString(), "privilege miscellaneous"));
        SummaryCards.Add(new SummaryCard("User trực tiếp", analysis.Users.Select(u => u.Id).Distinct().Count().ToString(),
            $"{analysis.Users.Count(u => u.IsDisabled)} đã disabled"));
        SummaryCards.Add(new SummaryCard("Team", analysis.Teams.Select(t => t.Id).Distinct().Count().ToString(),
            $"{analysis.TeamUsers.Select(t => t.UserId).Distinct().Count()} user qua team"));
        SummaryCards.Add(new SummaryCard("Tổng user hiệu lực",
            analysis.Users.Select(u => u.Id).Union(analysis.TeamUsers.Select(t => t.UserId)).Count().ToString(),
            "trực tiếp + qua team"));
        SummaryCards.Add(new SummaryCard("Model-driven App",
            analysis.Components.Count(c => c.Category == ComponentCategory.App).ToString(), "app có role này"));
        SummaryCards.Add(new SummaryCard("Form gán riêng",
            analysis.Components.Count(c => c.Category is ComponentCategory.Form or ComponentCategory.Dashboard && c.IsDirect).ToString(),
            "form/dashboard gán trực tiếp"));

        ComponentSummary.Clear();
        foreach (var category in ComponentCategory.All)
        {
            var items = analysis.Components.Where(c => c.Category == category).ToList();
            ComponentSummary.Add(new ComponentCategorySummary(category, items.Count, items.Count(c => c.IsDirect)));
        }

        Analysis = analysis;
        OnPropertyChanged(string.Empty);
    }

    private static ICollectionView CreateView<T>(List<T> items, Predicate<object> filter)
    {
        var view = new ListCollectionView(items) { Filter = filter };
        return view;
    }

    #endregion

    #region Filters

    [ObservableProperty] private string _entitySearchText = "";
    [ObservableProperty] private bool _onlyGrantedEntities = true;
    [ObservableProperty] private bool _onlyCustomEntities;
    [ObservableProperty] private string _miscSearchText = "";
    [ObservableProperty] private bool _onlyGrantedMisc = true;
    [ObservableProperty] private string _userSearchText = "";
    [ObservableProperty] private string _teamSearchText = "";
    [ObservableProperty] private string _teamUserSearchText = "";
    [ObservableProperty] private string _componentSearchText = "";
    [ObservableProperty] private string _componentCategoryFilter = AllCategories;
    [ObservableProperty] private bool _onlyDirectComponents;

    partial void OnEntitySearchTextChanged(string value) => EntityRowsView?.Refresh();
    partial void OnOnlyGrantedEntitiesChanged(bool value) => EntityRowsView?.Refresh();
    partial void OnOnlyCustomEntitiesChanged(bool value) => EntityRowsView?.Refresh();
    partial void OnMiscSearchTextChanged(string value) => MiscView?.Refresh();
    partial void OnOnlyGrantedMiscChanged(bool value) => MiscView?.Refresh();
    partial void OnUserSearchTextChanged(string value) => UsersView?.Refresh();
    partial void OnTeamSearchTextChanged(string value) => TeamsView?.Refresh();
    partial void OnTeamUserSearchTextChanged(string value) => TeamUsersView?.Refresh();
    partial void OnComponentSearchTextChanged(string value) => ComponentsView?.Refresh();
    partial void OnComponentCategoryFilterChanged(string value) => ComponentsView?.Refresh();
    partial void OnOnlyDirectComponentsChanged(bool value) => ComponentsView?.Refresh();

    private bool FilterEntity(object item) =>
        item is EntityPrivilegeRow row
        && (!OnlyGrantedEntities || row.HasAnyPrivilege)
        && (!OnlyCustomEntities || row.IsCustom)
        && (Contains(row.DisplayName, EntitySearchText) || Contains(row.LogicalName, EntitySearchText));

    private bool FilterMisc(object item) =>
        item is MiscPrivilegeRow row
        && (!OnlyGrantedMisc || row.IsGranted)
        && (Contains(row.Name, MiscSearchText) || Contains(row.Entity, MiscSearchText));

    private bool FilterUser(object item) =>
        item is RoleUser user
        && (Contains(user.FullName, UserSearchText) || Contains(user.DomainName, UserSearchText) || Contains(user.BusinessUnitName, UserSearchText));

    private bool FilterTeam(object item) =>
        item is RoleTeam team && (Contains(team.Name, TeamSearchText) || Contains(team.BusinessUnitName, TeamSearchText));

    private bool FilterTeamUser(object item) =>
        item is RoleTeamUser user
        && (Contains(user.FullName, TeamUserSearchText) || Contains(user.DomainName, TeamUserSearchText) || Contains(user.TeamName, TeamUserSearchText));

    private bool FilterComponent(object item) =>
        item is RoleComponent component
        && (ComponentCategoryFilter == AllCategories || component.Category == ComponentCategoryFilter)
        && (!OnlyDirectComponents || component.IsDirect)
        && (Contains(component.Name, ComponentSearchText)
            || Contains(component.EntityDisplayName, ComponentSearchText)
            || Contains(component.EntityLogicalName, ComponentSearchText));

    internal static bool Contains(string? source, string? search) =>
        string.IsNullOrWhiteSpace(search) || (source?.Contains(search.Trim(), StringComparison.CurrentCultureIgnoreCase) ?? false);

    #endregion

    #region Manage users & teams

    /// <summary>Các dòng đang chọn trên lưới Users (đồng bộ qua GridSelection).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedUsersText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveUsersCommand))]
    private IList? _selectedUsers;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedTeamsText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveTeamsCommand))]
    private IList? _selectedTeams;

    private List<RoleUser> PickedUsers => SelectedUsers?.OfType<RoleUser>().ToList() ?? [];
    private List<RoleTeam> PickedTeams => SelectedTeams?.OfType<RoleTeam>().ToList() ?? [];

    public string SelectedUsersText => PickedUsers.Count == 0 ? "" : $"Đã chọn {PickedUsers.Count} user";
    public string SelectedTeamsText => PickedTeams.Count == 0 ? "" : $"Đã chọn {PickedTeams.Count} team";

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private Task AddUserAsync() => AddPrincipalsAsync(isTeam: false);

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private Task AddTeamAsync() => AddPrincipalsAsync(isTeam: true);

    private bool CanRemoveUsers => PickedUsers.Count > 0;
    private bool CanRemoveTeams => PickedTeams.Count > 0;

    [RelayCommand(CanExecute = nameof(CanRemoveUsers))]
    private Task RemoveUsersAsync() =>
        RemovePrincipalsAsync(false, PickedUsers.Select(u => (u.Id, u.AssignedRoleId, u.FullName)).ToList());

    [RelayCommand(CanExecute = nameof(CanRemoveTeams))]
    private Task RemoveTeamsAsync() =>
        RemovePrincipalsAsync(true, PickedTeams.Select(t => (t.Id, t.AssignedRoleId, t.Name)).ToList());

    private async Task AddPrincipalsAsync(bool isTeam)
    {
        if (_service is null || Analysis is null)
            return;

        var service = _service;
        var analysis = Analysis;
        var picked = PrincipalPickerWindow.Show(
            App.Current.MainWindow,
            isTeam ? $"Thêm team vào role \"{analysis.Role.Name}\"" : $"Thêm user vào role \"{analysis.Role.Name}\"",
            isTeam ? text => service.SearchTeamsAsync(text) : text => service.SearchUsersAsync(text));
        if (picked is null || picked.Count == 0)
            return;

        await RunBusyAsync("Đang gán role...", async () =>
        {
            var errors = new List<string>();
            foreach (var principal in picked)
            {
                try
                {
                    await service.AssignRoleAsync(isTeam, principal, analysis.RoleCopies, analysis.Role.Name);
                }
                catch (Exception ex)
                {
                    errors.Add($"{principal.Name}: {ex.Message}");
                }
            }

            if (errors.Count > 0)
                Dialogs.ShowWarning("Một số mục không gán được:\n\n" + string.Join("\n", errors));
            StatusText = $"Đã gán role cho {picked.Count - errors.Count}/{picked.Count} {(isTeam ? "team" : "user")}.";
        });
        await LoadRoleAsync(analysis.Role);
    }

    private async Task RemovePrincipalsAsync(bool isTeam, List<(Guid Id, Guid AssignedRoleId, string Name)> items)
    {
        if (_service is null || Analysis is null || items.Count == 0)
            return;

        var kind = isTeam ? "team" : "user";
        var names = string.Join("\n", items.Take(15).Select(i => "• " + i.Name));
        if (items.Count > 15)
            names += $"\n... và {items.Count - 15} {kind} khác";
        if (!Dialogs.Confirm($"Gỡ role \"{Analysis.Role.Name}\" khỏi {items.Count} {kind} sau?\n\n{names}"))
            return;

        var service = _service;
        var role = Analysis.Role;
        await RunBusyAsync($"Đang gỡ role khỏi {items.Count} {kind}...", async () =>
        {
            var errors = new List<string>();
            var done = 0;
            foreach (var item in items)
            {
                BusyText = $"Đang gỡ role ({done + errors.Count + 1}/{items.Count}): {item.Name}";
                try
                {
                    await service.RemoveRoleAsync(isTeam, item.Id, item.AssignedRoleId, item.Name, role.Name);
                    done++;
                }
                catch (Exception ex)
                {
                    errors.Add($"{item.Name}: {ex.Message}");
                }
            }

            if (errors.Count > 0)
                Dialogs.ShowWarning("Một số mục không gỡ được:\n\n" + string.Join("\n", errors));
            StatusText = $"Đã gỡ role khỏi {done}/{items.Count} {kind}.";
        });
        await LoadRoleAsync(role);
    }

    #endregion

    #region Other commands

    /// <summary>Hiển thị dữ liệu mẫu (tham số --demo).</summary>
    public void LoadDemo()
    {
        var (roles, analysis) = DemoData.Create();
        foreach (var role in roles)
            Roles.Add(role);
        ConnectionText = "Chế độ demo – dữ liệu mẫu, chưa kết nối Dynamics 365";
        SelectedRole = analysis.Role;
        ApplyAnalysis(analysis);
        var (teams, teamAnalysis) = DemoData.CreateTeams(roles);
        TeamManager.LoadDemo(teams, teamAnalysis);
        var extended = DemoData.CreateExtended(roles, teams, teamAnalysis);
        UserManager.LoadDemo(extended.Users, extended.UserAnalysis);
        AppManager.LoadDemo(extended.Apps, extended.AppAnalysis);
        FieldSecurity.LoadDemo(extended.Profiles, extended.ProfileAnalysis);
        BusinessUnits.LoadDemo(extended.Index);
        StatusText = "Demo: chọn \"Kết nối\" để làm việc với môi trường thật.";
    }


    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void Export()
    {
        if (Analysis is null)
            return;

        var path = Dialogs.SaveExcel($"SecurityRole_{SafeFileName(Analysis.Role.Name)}_{DateTime.Now:yyyyMMdd_HHmm}.xlsx");
        if (path is null)
            return;

        try
        {
            ExcelExporter.ExportRoleAnalysis(Analysis, path);
            StatusText = "Đã xuất: " + path;
            if (Dialogs.Confirm("Xuất Excel thành công. Mở file ngay?"))
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Dialogs.ShowError(ex);
        }
    }

    /// <summary>Double-click team ở tab Teams của role.</summary>
    [RelayCommand]
    private void OpenRoleTeam(RoleTeam? team)
    {
        if (team is not null)
            OpenTeam(team.Id);
    }

    /// <summary>Double-click user ở tab Users / Users qua Team của role.</summary>
    [RelayCommand]
    private void OpenRoleUser(object? item)
    {
        var id = item switch { RoleUser u => u.Id, RoleTeamUser t => t.UserId, _ => Guid.Empty };
        if (id != Guid.Empty)
            _ = OpenUserAsync(id);
    }

    /// <summary>Chuyển sang chế độ Security Roles và mở role theo Id role gốc.</summary>
    internal void OpenRole(Guid rootRoleId)
    {
        var role = Roles.FirstOrDefault(r => r.Id == rootRoleId);
        if (role is null)
            return;
        SetModeSilently(AppMode.Roles);
        RoleSearchText = "";
        HideManagedRoles = false;
        if (ReferenceEquals(SelectedRole, role))
            _ = LoadRoleAsync(role);
        else
            SelectedRole = role;
    }

    [RelayCommand(CanExecute = nameof(IsConnected))]
    private void Compare()
    {
        if (_service is null)
            return;
        CompareWindow.Show(App.Current.MainWindow, new CompareViewModel(_service, Roles.ToList(), SelectedRole));
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void OpenInBrowser()
    {
        if (_service is null || Analysis is null)
            return;
        var url = $"{_service.OrganizationUrl}/biz/roles/edit.aspx?id={{{Analysis.Role.Id}}}";
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    internal static string SafeFileName(string name) =>
        string.Concat(name.Select(c => System.IO.Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

    #endregion
}
