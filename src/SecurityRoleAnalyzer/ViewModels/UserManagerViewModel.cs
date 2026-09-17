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

/// <summary>Chế độ quản lý theo user: role trực tiếp + qua team, quyền hiệu lực, sao chép quyền.</summary>
public sealed partial class UserManagerViewModel : ObservableObject
{
    private readonly MainViewModel _host;
    private CancellationTokenSource? _loadCts;
    private bool _suppressLoad;

    public UserManagerViewModel(MainViewModel host)
    {
        _host = host;
        UsersView = CollectionViewSource.GetDefaultView(Users);
        UsersView.Filter = FilterUser;
    }

    public bool IsLoaded { get; private set; }

    #region User list

    public ObservableCollection<UserInfo> Users { get; } = [];
    public ICollectionView UsersView { get; }

    [ObservableProperty] private string _userSearchText = "";
    [ObservableProperty] private bool _hideDisabled = true;
    [ObservableProperty] private bool _hideApplicationUsers;
    [ObservableProperty] private UserInfo? _selectedUser;

    public string UserCountText => $"{UsersView.Cast<object>().Count()} / {Users.Count} user";

    partial void OnUserSearchTextChanged(string value) => RefreshUsers();
    partial void OnHideDisabledChanged(bool value) => RefreshUsers();
    partial void OnHideApplicationUsersChanged(bool value) => RefreshUsers();

    private void RefreshUsers()
    {
        UsersView.Refresh();
        OnPropertyChanged(nameof(UserCountText));
    }

    private bool FilterUser(object item) =>
        item is UserInfo user
        && (!HideDisabled || !user.IsDisabled)
        && (!HideApplicationUsers || !user.IsApplicationUser)
        && (MainViewModel.Contains(user.FullName, UserSearchText)
            || MainViewModel.Contains(user.DomainName, UserSearchText)
            || MainViewModel.Contains(user.BusinessUnitName, UserSearchText));

    public async Task LoadListAsync()
    {
        if (_host.Service is not { } service)
            return;

        var selectedId = SelectedUser?.Id;
        var users = await service.GetUsersAsync();
        Users.Clear();
        foreach (var user in users)
            Users.Add(user);
        IsLoaded = true;
        RefreshUsers();
        if (selectedId is { } id)
            SetSelectedSilently(Users.FirstOrDefault(u => u.Id == id));
    }

    public void Clear()
    {
        IsLoaded = false;
        Analysis = null;
        SummaryCards.Clear();
        SetSelectedSilently(null);
        Users.Clear();
        OnPropertyChanged(string.Empty);
    }

    public async Task SelectUserAsync(Guid userId)
    {
        if (!IsLoaded)
            await _host.RunBusyAsync("Đang tải danh sách user...", LoadListAsync);

        var user = Users.FirstOrDefault(u => u.Id == userId);
        if (user is null)
            return;
        UserSearchText = "";
        HideDisabled = false;
        HideApplicationUsers = false;
        if (ReferenceEquals(SelectedUser, user))
            await LoadUserAsync(user);
        else
            SelectedUser = user;
    }

    private void SetSelectedSilently(UserInfo? user)
    {
        _suppressLoad = true;
        SelectedUser = user;
        _suppressLoad = false;
    }

    partial void OnSelectedUserChanged(UserInfo? value)
    {
        if (value is not null && !_suppressLoad)
            _ = LoadUserAsync(value);
    }

    [RelayCommand]
    private Task ReloadAsync() => SelectedUser is null ? Task.CompletedTask : LoadUserAsync(SelectedUser);

    private async Task LoadUserAsync(UserInfo user)
    {
        if (_host.Service is not { } service)
            return;

        _loadCts?.Cancel();
        var cts = _loadCts = new CancellationTokenSource();

        await _host.RunBusyAsync($"Đang phân tích user \"{user.FullName}\"...", async () =>
        {
            var progress = new Progress<string>(text => _host.BusyText = text);
            var watch = Stopwatch.StartNew();
            var analysis = await new UserAnalyzer(service).AnalyzeAsync(user, progress, cts.Token);
            if (cts.IsCancellationRequested)
                return;

            user.RoleCount = analysis.DirectRoles.Count;
            ApplyAnalysis(analysis);
            _host.StatusText = $"Phân tích user \"{user.FullName}\" xong trong {watch.Elapsed.TotalSeconds:0.0}s";
        });
    }

    #endregion

    #region Analysis

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAnalysis))]
    [NotifyCanExecuteChangedFor(nameof(AddRolesCommand), nameof(AddToTeamsCommand), nameof(ExportCommand), nameof(OpenInBrowserCommand),
        nameof(CopyAccessToCommand), nameof(CopyAccessFromCommand))]
    private UserAnalysis? _analysis;

    public bool HasAnalysis => Analysis is not null;

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];

    public ICollectionView? RolesView { get; private set; }
    public ICollectionView? TeamsView { get; private set; }
    public ICollectionView? EntityRowsView { get; private set; }
    public ICollectionView? MiscView { get; private set; }
    public ICollectionView? AppsView { get; private set; }
    public ICollectionView? ProfilesView { get; private set; }

    public string RolesTabHeader => Analysis is null ? "Security Roles" : $"Security Roles ({Analysis.AllRoles.Count()})";
    public string TeamsTabHeader => Analysis is null ? "Teams" : $"Teams ({Analysis.Teams.Count})";
    public string EntityTabHeader => Analysis is null ? "Quyền hiệu lực" : $"Quyền hiệu lực ({Analysis.EntityRows.Count(r => r.HasAnyPrivilege)})";
    public string MiscTabHeader => Analysis is null ? "Quyền khác" : $"Quyền khác ({Analysis.MiscPrivileges.Count(m => m.IsGranted)})";
    public string AppsTabHeader => Analysis is null ? "Apps" : $"Apps ({Analysis.Apps.Count})";
    public string ProfilesTabHeader => Analysis is null ? "Field Security" : $"Field Security ({Analysis.FieldProfiles.Count})";
    public string FindingsHeader => Analysis is null ? "" : $"Phát hiện & rủi ro ({Analysis.Findings.Count})";
    public string WarningsText => Analysis is null ? "" : string.Join(Environment.NewLine, Analysis.Warnings);
    public bool HasWarnings => Analysis?.Warnings.Count > 0;

    public string UserSubtitle => Analysis?.User is not { } u
        ? ""
        : $"{u.DomainName}  ·  Business Unit: {u.BusinessUnitName}  ·  {u.AccessModeText}  ·  {u.StatusText}"
          + (string.IsNullOrEmpty(u.Title) ? "" : $"  ·  {u.Title}") + $"  ·  Id: {u.Id}";

    private void ApplyAnalysis(UserAnalysis analysis)
    {
        RolesView = new ListCollectionView(analysis.AllRoles.OrderBy(r => r.Name).ThenBy(r => !r.IsDirect).ToList()) { Filter = FilterRole };
        TeamsView = new ListCollectionView(analysis.Teams);
        EntityRowsView = new ListCollectionView(analysis.EntityRows) { Filter = FilterEntity };
        MiscView = new ListCollectionView(analysis.MiscPrivileges) { Filter = FilterMisc };
        AppsView = new ListCollectionView(analysis.Apps);
        ProfilesView = new ListCollectionView(analysis.FieldProfiles);

        SummaryCards.Clear();
        var granted = analysis.EntityRows.Where(r => r.HasAnyPrivilege).ToList();
        SummaryCards.Add(new SummaryCard("Role trực tiếp", analysis.DirectRoles.Count.ToString(), "gán trực tiếp cho user"));
        SummaryCards.Add(new SummaryCard("Role qua team", analysis.TeamRoles.Select(r => r.RootRoleId).Distinct().Count().ToString(), $"từ {analysis.Teams.Count} team"));
        SummaryCards.Add(new SummaryCard("Entity có quyền", granted.Count.ToString(), "quyền hiệu lực gộp"));
        SummaryCards.Add(new SummaryCard("Mức Organization", granted.Count(r => r.Cells.Any(c => c.Depth == PrivilegeDepth.Organization)).ToString(), "entity có quyền mức Org"));
        SummaryCards.Add(new SummaryCard("Model-driven App", analysis.Apps.Count.ToString(), "app mở được"));
        SummaryCards.Add(new SummaryCard("Field Security", analysis.FieldProfiles.Select(p => p.ProfileId).Distinct().Count().ToString(), "profile áp dụng"));

        Analysis = analysis;
        OnPropertyChanged(string.Empty);
    }

    [ObservableProperty] private string _roleSearchText = "";
    [ObservableProperty] private string _entitySearchText = "";
    [ObservableProperty] private bool _onlyGrantedEntities = true;
    [ObservableProperty] private string _miscSearchText = "";

    partial void OnRoleSearchTextChanged(string value) => RolesView?.Refresh();
    partial void OnEntitySearchTextChanged(string value) => EntityRowsView?.Refresh();
    partial void OnOnlyGrantedEntitiesChanged(bool value) => EntityRowsView?.Refresh();
    partial void OnMiscSearchTextChanged(string value) => MiscView?.Refresh();

    private bool FilterRole(object item) =>
        item is UserRoleAssignment role && (MainViewModel.Contains(role.Name, RoleSearchText) || MainViewModel.Contains(role.SourceText, RoleSearchText));

    private bool FilterEntity(object item) =>
        item is EntityPrivilegeRow row
        && (!OnlyGrantedEntities || row.HasAnyPrivilege)
        && (MainViewModel.Contains(row.DisplayName, EntitySearchText)
            || MainViewModel.Contains(row.LogicalName, EntitySearchText)
            || MainViewModel.Contains(row.SourcesText, EntitySearchText));

    private bool FilterMisc(object item) =>
        item is MiscPrivilegeRow row && row.IsGranted
        && (MainViewModel.Contains(row.Name, MiscSearchText) || MainViewModel.Contains(row.SourcesText, MiscSearchText));

    #endregion

    #region Manage roles & teams

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedRolesText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveRolesCommand))]
    private IList? _selectedRoles;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedTeamsText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveFromTeamsCommand))]
    private IList? _selectedTeams;

    private List<UserRoleAssignment> PickedRoles => SelectedRoles?.OfType<UserRoleAssignment>().ToList() ?? [];
    private List<TeamInfo> PickedTeams => SelectedTeams?.OfType<TeamInfo>().ToList() ?? [];

    public string SelectedRolesText => PickedRoles.Count == 0 ? "" : $"Đã chọn {PickedRoles.Count} role";
    public string SelectedTeamsText => PickedTeams.Count == 0 ? "" : $"Đã chọn {PickedTeams.Count} team";

    private bool CanRemoveRoles => PickedRoles.Count > 0;
    private bool CanRemoveFromTeams => PickedTeams.Count > 0;

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task AddRolesAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var user = analysis.User;
        var assigned = analysis.DirectRoles.Select(r => r.RootRoleId).ToHashSet();
        var available = _host.Roles.Where(r => !assigned.Contains(r.Id)).ToList();
        var picked = PrincipalPickerWindow.Show(
            App.Current.MainWindow,
            $"Gán security role cho user \"{user.FullName}\"",
            text => Task.FromResult(available
                .Where(r => MainViewModel.Contains(r.Name, text))
                .Select(r => new PrincipalSearchResult { Id = r.Id, Name = r.Name, Detail = r.ManagedText, BusinessUnitName = r.BusinessUnitName })
                .ToList()),
            actionText: "Gán role",
            hint: $"Role sẽ được gán theo Business Unit của user ({user.BusinessUnitName}).",
            searchOnOpen: true);
        if (picked is null || picked.Count == 0)
            return;

        await RunBatchAsync("Đang gán role", picked, p => p.Name,
            p => service.AssignRootRoleAsync(false, user.Id, user.FullName, user.BusinessUnitId, user.BusinessUnitName, p.Id, p.Name));
        await LoadUserAsync(user);
    }

    [RelayCommand(CanExecute = nameof(CanRemoveRoles))]
    private async Task RemoveRolesAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var picked = PickedRoles;
        var viaTeam = picked.Where(r => !r.IsDirect).ToList();
        var direct = picked.Where(r => r.IsDirect).ToList();
        if (viaTeam.Count > 0)
        {
            Dialogs.ShowWarning("Các role sau được nhận qua team nên không gỡ trực tiếp được – hãy gỡ user khỏi team hoặc gỡ role khỏi team:\n\n"
                                + string.Join("\n", viaTeam.Select(r => $"• {r.Name} ({r.SourceText})")));
        }
        if (direct.Count == 0 || !Dialogs.Confirm($"Gỡ {direct.Count} role trực tiếp khỏi user \"{analysis.User.FullName}\"?\n\n"
                                                  + string.Join("\n", direct.Select(r => "• " + r.Name))))
            return;

        var user = analysis.User;
        await RunBatchAsync("Đang gỡ role", direct, r => r.Name,
            r => service.RemoveRoleAsync(false, user.Id, r.AssignedRoleId, user.FullName, r.Name));
        await LoadUserAsync(user);
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task AddToTeamsAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var user = analysis.User;
        var current = analysis.Teams.Select(t => t.Id).ToHashSet();
        var picked = PrincipalPickerWindow.Show(
            App.Current.MainWindow,
            $"Thêm user \"{user.FullName}\" vào team",
            async text => (await service.SearchTeamsAsync(text)).Where(t => !current.Contains(t.Id)).ToList(),
            actionText: "Thêm vào team",
            hint: "Chỉ thêm được vào Owner/Access team (không phải default team hay team Entra ID).");
        if (picked is null || picked.Count == 0)
            return;

        await RunBatchAsync("Đang thêm vào team", picked, t => t.Name,
            t => service.AddTeamMembersAsync(t.Id, [user.Id], t.Name, user.FullName));
        await LoadUserAsync(user);
    }

    [RelayCommand(CanExecute = nameof(CanRemoveFromTeams))]
    private async Task RemoveFromTeamsAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var teams = PickedTeams.Where(t => t.CanManageMembers).ToList();
        var locked = PickedTeams.Except(teams).ToList();
        if (locked.Count > 0)
            Dialogs.ShowWarning("Không thể gỡ khỏi default team hoặc team Entra ID:\n\n" + string.Join("\n", locked.Select(t => "• " + t.Name)));
        if (teams.Count == 0 || !Dialogs.Confirm($"Gỡ user \"{analysis.User.FullName}\" khỏi {teams.Count} team?\n\n" + string.Join("\n", teams.Select(t => "• " + t.Name))))
            return;

        var user = analysis.User;
        await RunBatchAsync("Đang gỡ khỏi team", teams, t => t.Name,
            t => service.RemoveTeamMembersAsync(t.Id, [user.Id], t.Name, user.FullName));
        await LoadUserAsync(user);
    }

    /// <summary>Sao chép role trực tiếp, team và field security profile của user đang xem sang các user khác.</summary>
    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task CopyAccessToAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } source)
            return;

        var targets = PrincipalPickerWindow.Show(
            App.Current.MainWindow,
            $"Sao chép quyền của \"{source.User.FullName}\" sang user khác",
            async text => (await service.SearchUsersAsync(text)).Where(u => u.Id != source.User.Id).ToList(),
            actionText: "Chọn user đích",
            hint: "Tick các user sẽ nhận quyền giống user đang xem.");
        if (targets is null || targets.Count == 0)
            return;

        var options = CopyAccessWindow.Show(App.Current.MainWindow, source, string.Join(", ", targets.Select(t => t.Name)));
        if (options is null)
            return;

        await _host.RunBusyAsync("Đang sao chép quyền...", async () =>
        {
            var errors = new List<string>();
            foreach (var target in targets)
                errors.AddRange(await CopyAccessAsync(service, source, target, options));
            ReportErrors(errors, $"Đã sao chép quyền sang {targets.Count} user.");
        });
        await LoadUserAsync(source.User);
    }

    /// <summary>Lấy quyền từ một user khác áp cho user đang xem.</summary>
    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task CopyAccessFromAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } target)
            return;

        var picked = PrincipalPickerWindow.Show(
            App.Current.MainWindow,
            $"Chọn user nguồn để sao chép quyền cho \"{target.User.FullName}\"",
            async text => (await service.SearchUsersAsync(text)).Where(u => u.Id != target.User.Id).ToList(),
            actionText: "Chọn làm user nguồn",
            hint: "Chọn đúng 1 user nguồn.");
        if (picked is not { Count: 1 })
        {
            if (picked is { Count: > 1 })
                Dialogs.ShowWarning("Vui lòng chỉ chọn 1 user nguồn.");
            return;
        }

        UserAnalysis? source = null;
        await _host.RunBusyAsync("Đang đọc quyền của user nguồn...", async () =>
        {
            var info = Users.FirstOrDefault(u => u.Id == picked[0].Id) ?? new UserInfo
            {
                Id = picked[0].Id, FullName = picked[0].Name, DomainName = picked[0].Detail,
                BusinessUnitId = picked[0].BusinessUnitId, BusinessUnitName = picked[0].BusinessUnitName,
            };
            source = await new UserAnalyzer(service).AnalyzeAsync(info, new Progress<string>(t => _host.BusyText = t), CancellationToken.None);
        });
        if (source is null)
            return;

        var options = CopyAccessWindow.Show(App.Current.MainWindow, source, target.User.FullName);
        if (options is null)
            return;

        var targetPrincipal = new PrincipalSearchResult
        {
            Id = target.User.Id, Name = target.User.FullName,
            BusinessUnitId = target.User.BusinessUnitId, BusinessUnitName = target.User.BusinessUnitName,
        };
        await _host.RunBusyAsync("Đang sao chép quyền...", async () =>
        {
            var errors = await CopyAccessAsync(service, source, targetPrincipal, options);
            ReportErrors(errors, $"Đã sao chép quyền từ \"{source.User.FullName}\".");
        });
        await LoadUserAsync(target.User);
    }

    private async Task<List<string>> CopyAccessAsync(DataverseService service, UserAnalysis source, PrincipalSearchResult target, CopyAccessOptions options)
    {
        var errors = new List<string>();
        _host.BusyText = $"Đang đọc quyền hiện tại của \"{target.Name}\"...";
        var targetRoles = await service.GetUserDirectRolesAsync(target.Id);
        var targetTeams = await service.GetUserTeamsAsync(target.Id);
        var targetProfiles = await service.GetFieldProfilesOfUserAsync(target.Id, []);

        async Task Try(string what, Func<Task> action)
        {
            try
            {
                _host.BusyText = $"{target.Name}: {what}";
                await action();
            }
            catch (Exception ex)
            {
                errors.Add($"{target.Name} – {what}: {ex.Message}");
            }
        }

        if (options.Roles)
        {
            var sourceRoles = source.DirectRoles.DistinctBy(r => r.RootRoleId).ToList();
            foreach (var role in sourceRoles.Where(r => targetRoles.All(t => t.RootRoleId != r.RootRoleId)))
                await Try($"gán role {role.Name}", () => service.AssignRootRoleAsync(false, target.Id, target.Name, target.BusinessUnitId, target.BusinessUnitName, role.RootRoleId, role.Name));
            if (options.RemoveExtra)
            {
                foreach (var role in targetRoles.Where(t => sourceRoles.All(r => r.RootRoleId != t.RootRoleId)))
                    await Try($"gỡ role {role.Name}", () => service.RemoveRoleAsync(false, target.Id, role.AssignedRoleId, target.Name, role.Name));
            }
        }

        if (options.Teams)
        {
            var sourceTeams = source.Teams.Where(t => t.CanManageMembers).ToList();
            foreach (var team in sourceTeams.Where(s => targetTeams.All(t => t.Id != s.Id)))
                await Try($"thêm vào team {team.Name}", () => service.AddTeamMembersAsync(team.Id, [target.Id], team.Name, target.Name));
            if (options.RemoveExtra)
            {
                foreach (var team in targetTeams.Where(t => t.CanManageMembers && sourceTeams.All(s => s.Id != t.Id)))
                    await Try($"gỡ khỏi team {team.Name}", () => service.RemoveTeamMembersAsync(team.Id, [target.Id], team.Name, target.Name));
            }
        }

        if (options.FieldProfiles)
        {
            var sourceProfiles = source.FieldProfiles.Where(p => p.IsDirect).DistinctBy(p => p.ProfileId).ToList();
            foreach (var profile in sourceProfiles.Where(p => targetProfiles.All(t => t.ProfileId != p.ProfileId)))
                await Try($"thêm vào profile {profile.Name}", () => service.AssociateFieldProfileAsync(profile.ProfileId, profile.Name, false, [(target.Id, target.Name)]));
            if (options.RemoveExtra)
            {
                foreach (var profile in targetProfiles.Where(t => t.IsDirect && sourceProfiles.All(p => p.ProfileId != t.ProfileId)))
                    await Try($"gỡ khỏi profile {profile.Name}", () => service.DisassociateFieldProfileAsync(profile.ProfileId, profile.Name, false, [(target.Id, target.Name)]));
            }
        }

        return errors;
    }

    private async Task RunBatchAsync<T>(string title, IReadOnlyList<T> items, Func<T, string> name, Func<T, Task> action)
    {
        await _host.RunBusyAsync(title + "...", async () =>
        {
            var errors = new List<string>();
            for (var i = 0; i < items.Count; i++)
            {
                _host.BusyText = $"{title} ({i + 1}/{items.Count}): {name(items[i])}";
                try
                {
                    await action(items[i]);
                }
                catch (Exception ex)
                {
                    errors.Add($"{name(items[i])}: {ex.Message}");
                }
            }
            ReportErrors(errors, $"{title}: {items.Count - errors.Count}/{items.Count} thành công.");
        });
    }

    private void ReportErrors(List<string> errors, string successText)
    {
        if (errors.Count > 0)
            Dialogs.ShowWarning("Một số thao tác không thành công:\n\n" + string.Join("\n", errors.Take(30)));
        _host.StatusText = successText + (errors.Count > 0 ? $" ({errors.Count} lỗi)" : "");
    }

    #endregion

    #region Other commands

    [RelayCommand]
    private void OpenRole(UserRoleAssignment? role)
    {
        if (role is not null)
            _host.OpenRole(role.RootRoleId);
    }

    [RelayCommand]
    private void OpenTeam(TeamInfo? team)
    {
        if (team is not null)
            _host.OpenTeam(team.Id);
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void Export()
    {
        if (Analysis is not { } a)
            return;

        _host.ExportWorkbook($"User_{MainViewModel.SafeFileName(a.User.FullName)}", workbook =>
        {
            ExcelExporter.AddInfoSheet(workbook, "Tong quan",
                [("User", a.User.FullName), ("Username", a.User.DomainName), ("Email", a.User.Email), ("Business Unit", a.User.BusinessUnitName),
                 ("Access mode", a.User.AccessModeText), ("Trạng thái", a.User.StatusText), ("Id", a.User.Id.ToString())],
                a.Findings);
            ExcelExporter.AddSheet(workbook, "Security Roles", a.AllRoles,
                new ExportColumn<UserRoleAssignment>("Role", r => r.Name),
                new ExportColumn<UserRoleAssignment>("Nguồn", r => r.SourceText),
                new ExportColumn<UserRoleAssignment>("Business Unit", r => r.BusinessUnitName),
                new ExportColumn<UserRoleAssignment>("Managed", r => r.ManagedText));
            ExcelExporter.AddSheet(workbook, "Teams", a.Teams,
                new ExportColumn<TeamInfo>("Team", t => t.Name),
                new ExportColumn<TeamInfo>("Loại", t => t.TeamTypeText),
                new ExportColumn<TeamInfo>("Business Unit", t => t.BusinessUnitName),
                new ExportColumn<TeamInfo>("Số role", t => t.RoleCount));
            ExcelExporter.AddEntityPrivilegeSheet(workbook, "Quyen hieu luc", a.EntityRows, includeSources: true);
            ExcelExporter.AddSheet(workbook, "Quyen khac", a.MiscPrivileges.Where(m => m.IsGranted),
                new ExportColumn<MiscPrivilegeRow>("Privilege", m => m.Name),
                new ExportColumn<MiscPrivilegeRow>("Mức", m => m.DepthText),
                new ExportColumn<MiscPrivilegeRow>("Từ role", m => m.SourcesText));
            ExcelExporter.AddSheet(workbook, "Apps", a.Apps,
                new ExportColumn<RoleComponent>("App", x => x.Name),
                new ExportColumn<RoleComponent>("Unique Name", x => x.SubType));
            ExcelExporter.AddSheet(workbook, "Field Security", a.FieldProfiles,
                new ExportColumn<FieldProfileAssignment>("Profile", p => p.Name),
                new ExportColumn<FieldProfileAssignment>("Nguồn", p => p.SourceText));
        });
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void OpenInBrowser()
    {
        if (Analysis is not null)
            _host.OpenRecord("systemuser", Analysis.User.Id);
    }

    public void LoadDemo(List<UserInfo> users, UserAnalysis analysis)
    {
        Users.Clear();
        foreach (var user in users)
            Users.Add(user);
        IsLoaded = true;
        RefreshUsers();
        SetSelectedSilently(users.First(u => u.Id == analysis.User.Id));
        ApplyAnalysis(analysis);
    }

    #endregion
}
