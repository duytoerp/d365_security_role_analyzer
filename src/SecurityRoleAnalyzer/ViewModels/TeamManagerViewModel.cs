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

/// <summary>Chế độ quản lý theo team: role của team, thành viên, quyền hiệu lực.</summary>
public sealed partial class TeamManagerViewModel : ObservableObject
{
    private readonly MainViewModel _host;
    private CancellationTokenSource? _loadCts;
    // true khi đổi SelectedTeam bằng code mà không muốn phân tích lại.
    private bool _suppressLoad;

    public TeamManagerViewModel(MainViewModel host)
    {
        _host = host;
        TeamsView = CollectionViewSource.GetDefaultView(Teams);
        TeamsView.Filter = FilterTeam;
    }

    #region Team list

    public bool IsLoaded { get; private set; }

    public ObservableCollection<TeamInfo> Teams { get; } = [];
    public ICollectionView TeamsView { get; }
    public IReadOnlyList<string> TeamTypeFilters { get; } = [TeamTypes.All, .. TeamTypes.Names];

    [ObservableProperty] private string _teamSearchText = "";
    [ObservableProperty] private string _teamTypeFilter = TeamTypes.All;
    [ObservableProperty] private bool _onlyTeamsWithRoles;
    [ObservableProperty] private TeamInfo? _selectedTeam;

    public string TeamCountText => $"{TeamsView.Cast<object>().Count()} / {Teams.Count} team";

    partial void OnTeamSearchTextChanged(string value) => RefreshTeams();
    partial void OnTeamTypeFilterChanged(string value) => RefreshTeams();
    partial void OnOnlyTeamsWithRolesChanged(bool value) => RefreshTeams();

    private void RefreshTeams()
    {
        TeamsView.Refresh();
        OnPropertyChanged(nameof(TeamCountText));
    }

    private bool FilterTeam(object item) =>
        item is TeamInfo team
        && (TeamTypeFilter == TeamTypes.All || team.TeamTypeText == TeamTypeFilter)
        && (!OnlyTeamsWithRoles || team.RoleCount > 0)
        && (MainViewModel.Contains(team.Name, TeamSearchText) || MainViewModel.Contains(team.BusinessUnitName, TeamSearchText));

    public async Task LoadTeamsAsync()
    {
        if (_host.Service is not { } service)
            return;

        var selectedId = SelectedTeam?.Id;
        var teams = await service.GetTeamsAsync();
        SetTeams(teams);
        IsLoaded = true;
        if (selectedId is { } id)
            SetSelectedTeamSilently(Teams.FirstOrDefault(t => t.Id == id));
    }

    private void SetTeams(IEnumerable<TeamInfo> teams)
    {
        Teams.Clear();
        foreach (var team in teams)
            Teams.Add(team);
        OnPropertyChanged(nameof(TeamCountText));
    }

    /// <summary>Chọn team theo Id (dùng khi điều hướng từ chế độ Security Roles).</summary>
    public void SelectTeam(Guid teamId)
    {
        var team = Teams.FirstOrDefault(t => t.Id == teamId);
        if (team is null)
            return;
        TeamSearchText = "";
        TeamTypeFilter = TeamTypes.All;
        OnlyTeamsWithRoles = false;
        if (ReferenceEquals(SelectedTeam, team))
            _ = LoadTeamAsync(team);
        else
            SelectedTeam = team;
    }

    private void SetSelectedTeamSilently(TeamInfo? team)
    {
        _suppressLoad = true;
        SelectedTeam = team;
        _suppressLoad = false;
    }

    partial void OnSelectedTeamChanged(TeamInfo? value)
    {
        if (value is not null && !_suppressLoad)
            _ = LoadTeamAsync(value);
    }

    [RelayCommand]
    private Task ReloadTeamAsync() => SelectedTeam is null ? Task.CompletedTask : LoadTeamAsync(SelectedTeam);

    private async Task LoadTeamAsync(TeamInfo team)
    {
        if (_host.Service is not { } service)
            return;

        _loadCts?.Cancel();
        var cts = _loadCts = new CancellationTokenSource();

        await _host.RunBusyAsync($"Đang phân tích team \"{team.Name}\"...", async () =>
        {
            var progress = new Progress<string>(text => _host.BusyText = text);
            var watch = Stopwatch.StartNew();
            var analysis = await new TeamAnalyzer(service).AnalyzeAsync(team, progress, cts.Token);
            if (cts.IsCancellationRequested)
                return;

            team.RoleCount = analysis.Roles.Count;
            ApplyAnalysis(analysis);
            _host.StatusText = $"Phân tích team \"{team.Name}\" xong trong {watch.Elapsed.TotalSeconds:0.0}s" +
                               (analysis.Warnings.Count > 0 ? $" – {analysis.Warnings.Count} cảnh báo (xem tab Tổng quan)" : "");
        });
    }

    #endregion

    #region Analysis

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAnalysis))]
    [NotifyCanExecuteChangedFor(nameof(AddRolesCommand), nameof(AddMembersCommand), nameof(ExportCommand), nameof(OpenInBrowserCommand))]
    private TeamAnalysis? _analysis;

    public bool HasAnalysis => Analysis is not null;

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];

    public ICollectionView? RolesView { get; private set; }
    public ICollectionView? MembersView { get; private set; }
    public ICollectionView? EntityRowsView { get; private set; }
    public ICollectionView? MiscView { get; private set; }
    public ICollectionView? AppsView { get; private set; }

    public string RolesTabHeader => Analysis is null ? "Security Roles" : $"Security Roles ({Analysis.Roles.Count})";
    public string MembersTabHeader => Analysis is null ? "Thành viên" : $"Thành viên ({Analysis.Members.Count})";
    public string EntityTabHeader => Analysis is null ? "Quyền hiệu lực" : $"Quyền hiệu lực ({Analysis.EntityRows.Count(r => r.HasAnyPrivilege)})";
    public string MiscTabHeader => Analysis is null ? "Quyền khác" : $"Quyền khác ({Analysis.MiscPrivileges.Count(m => m.IsGranted)})";
    public string AppsTabHeader => Analysis is null ? "Apps" : $"Apps ({Analysis.Apps.Count})";
    public string FindingsHeader => Analysis is null ? "" : $"Phát hiện & rủi ro ({Analysis.Findings.Count})";
    public string WarningsText => Analysis is null ? "" : string.Join(Environment.NewLine, Analysis.Warnings);
    public bool HasWarnings => Analysis?.Warnings.Count > 0;

    public string TeamSubtitle => Analysis?.Team is not { } t
        ? ""
        : $"Business Unit: {t.BusinessUnitName}  ·  {t.TeamTypeText}" +
          (t.IsDefault ? "  ·  Default team" : "") +
          (string.IsNullOrEmpty(t.AdministratorName) ? "" : $"  ·  Admin: {t.AdministratorName}") +
          (t.EntraObjectId is { } oid ? $"  ·  Entra Object Id: {oid}" : "") +
          $"  ·  Id: {t.Id}";

    public bool CanManageMembers => Analysis?.Team.CanManageMembers == true;

    public string MembersNote => Analysis?.Team switch
    {
        null => "",
        { IsDefault: true } => "Default team của Business Unit: thành viên do hệ thống tự quản lý theo BU, không thể thêm/gỡ.",
        { TeamType: 2 or 3 } => "Team Microsoft Entra ID: thêm/gỡ thành viên trong nhóm Entra ID. Danh sách chỉ gồm user đã từng truy cập môi trường.",
        _ => "",
    };

    public bool HasMembersNote => MembersNote.Length > 0;

    private void ApplyAnalysis(TeamAnalysis analysis)
    {
        RolesView = new ListCollectionView(analysis.Roles) { Filter = FilterRole };
        MembersView = new ListCollectionView(analysis.Members) { Filter = FilterMember };
        EntityRowsView = new ListCollectionView(analysis.EntityRows) { Filter = FilterEntity };
        MiscView = new ListCollectionView(analysis.MiscPrivileges) { Filter = FilterMisc };
        AppsView = new ListCollectionView(analysis.Apps)
        {
            Filter = o => o is RoleComponent c && (MainViewModel.Contains(c.Name, AppSearchText) || MainViewModel.Contains(c.SubType, AppSearchText)),
        };

        SummaryCards.Clear();
        var granted = analysis.EntityRows.Where(r => r.HasAnyPrivilege).ToList();
        SummaryCards.Add(new SummaryCard("Security Role", analysis.Roles.Count.ToString(), "role gán cho team"));
        SummaryCards.Add(new SummaryCard("Thành viên", analysis.Members.Count.ToString(), $"{analysis.Members.Count(m => m.IsDisabled)} đã disabled"));
        SummaryCards.Add(new SummaryCard("Entity có quyền", granted.Count.ToString(), "quyền hiệu lực gộp từ các role"));
        SummaryCards.Add(new SummaryCard("Mức Organization", granted.Count(r => r.Cells.Any(c => c.Depth == PrivilegeDepth.Organization)).ToString(), "entity có ít nhất 1 quyền mức Org"));
        SummaryCards.Add(new SummaryCard("Quyền khác", analysis.MiscPrivileges.Count(m => m.IsGranted).ToString(), "privilege miscellaneous"));
        SummaryCards.Add(new SummaryCard("Model-driven App", analysis.Apps.Count.ToString(), "app thành viên mở được"));

        Analysis = analysis;
        OnPropertyChanged(string.Empty);
    }

    public void Clear()
    {
        Analysis = null;
        SummaryCards.Clear();
        SetSelectedTeamSilently(null);
        Teams.Clear();
        IsLoaded = false;
        OnPropertyChanged(string.Empty);
    }

    #endregion

    #region Filters

    [ObservableProperty] private string _roleSearchText = "";
    [ObservableProperty] private string _memberSearchText = "";
    [ObservableProperty] private string _entitySearchText = "";
    [ObservableProperty] private bool _onlyGrantedEntities = true;
    [ObservableProperty] private bool _onlyCustomEntities;
    [ObservableProperty] private string _miscSearchText = "";

    partial void OnRoleSearchTextChanged(string value) => RolesView?.Refresh();

    [ObservableProperty] private string _appSearchText = "";
    partial void OnAppSearchTextChanged(string value) => AppsView?.Refresh();
    partial void OnMemberSearchTextChanged(string value) => MembersView?.Refresh();
    partial void OnEntitySearchTextChanged(string value) => EntityRowsView?.Refresh();
    partial void OnOnlyGrantedEntitiesChanged(bool value) => EntityRowsView?.Refresh();
    partial void OnOnlyCustomEntitiesChanged(bool value) => EntityRowsView?.Refresh();
    partial void OnMiscSearchTextChanged(string value) => MiscView?.Refresh();

    private bool FilterRole(object item) =>
        item is TeamRoleAssignment role && MainViewModel.Contains(role.Name, RoleSearchText);

    private bool FilterMember(object item) =>
        item is TeamMember member
        && (MainViewModel.Contains(member.FullName, MemberSearchText)
            || MainViewModel.Contains(member.DomainName, MemberSearchText)
            || MainViewModel.Contains(member.BusinessUnitName, MemberSearchText));

    private bool FilterEntity(object item) =>
        item is EntityPrivilegeRow row
        && (!OnlyGrantedEntities || row.HasAnyPrivilege)
        && (!OnlyCustomEntities || row.IsCustom)
        && (MainViewModel.Contains(row.DisplayName, EntitySearchText)
            || MainViewModel.Contains(row.LogicalName, EntitySearchText)
            || MainViewModel.Contains(row.SourcesText, EntitySearchText));

    private bool FilterMisc(object item) =>
        item is MiscPrivilegeRow row
        && row.IsGranted
        && (MainViewModel.Contains(row.Name, MiscSearchText) || MainViewModel.Contains(row.SourcesText, MiscSearchText));

    #endregion

    #region Manage roles & members

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedRolesText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveRolesCommand))]
    private IList? _selectedRoles;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedMembersText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveMembersCommand))]
    private IList? _selectedMembers;

    private List<TeamRoleAssignment> PickedRoles => SelectedRoles?.OfType<TeamRoleAssignment>().ToList() ?? [];
    private List<TeamMember> PickedMembers => SelectedMembers?.OfType<TeamMember>().ToList() ?? [];

    public string SelectedRolesText => PickedRoles.Count == 0 ? "" : $"Đã chọn {PickedRoles.Count} role";
    public string SelectedMembersText => PickedMembers.Count == 0 ? "" : $"Đã chọn {PickedMembers.Count} thành viên";

    private bool CanRemoveRoles => PickedRoles.Count > 0;
    private bool CanAddMembers => CanManageMembers;
    private bool CanRemoveMembers => CanManageMembers && PickedMembers.Count > 0;

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task AddRolesAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var assigned = analysis.Roles.Select(r => r.RootRoleId).ToHashSet();
        var available = _host.Roles.Where(r => !assigned.Contains(r.Id)).ToList();
        var picked = PrincipalPickerWindow.Show(
            App.Current.MainWindow,
            $"Gán security role cho team \"{analysis.Team.Name}\"",
            text => Task.FromResult(available
                .Where(r => MainViewModel.Contains(r.Name, text))
                .Select(r => new PrincipalSearchResult { Id = r.Id, Name = r.Name, Detail = r.ManagedText, BusinessUnitName = r.BusinessUnitName })
                .ToList()),
            actionText: "Gán role",
            hint: $"Role sẽ được gán theo Business Unit của team ({analysis.Team.BusinessUnitName}).",
            searchOnOpen: true);
        if (picked is null || picked.Count == 0)
            return;

        await _host.RunBusyAsync("Đang gán role cho team...", async () =>
        {
            var errors = new List<string>();
            var index = 0;
            foreach (var item in picked)
            {
                _host.BusyText = $"Đang gán role ({++index}/{picked.Count}): {item.Name}";
                var role = available.First(r => r.Id == item.Id);
                try
                {
                    await service.AssignRoleToTeamAsync(analysis.Team, role);
                }
                catch (Exception ex)
                {
                    errors.Add($"{role.Name}: {ex.Message}");
                }
            }

            if (errors.Count > 0)
                Dialogs.ShowWarning("Một số role không gán được:\n\n" + string.Join("\n", errors));
            _host.StatusText = $"Đã gán {picked.Count - errors.Count}/{picked.Count} role cho team \"{analysis.Team.Name}\".";
        });
        await LoadTeamAsync(analysis.Team);
    }

    [RelayCommand(CanExecute = nameof(CanRemoveRoles))]
    private async Task RemoveRolesAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var roles = PickedRoles;
        if (!Dialogs.Confirm($"Gỡ {roles.Count} role khỏi team \"{analysis.Team.Name}\"?\n\n{Bullets(roles.Select(r => r.Name))}"))
            return;

        await _host.RunBusyAsync("Đang gỡ role khỏi team...", async () =>
        {
            var errors = new List<string>();
            var index = 0;
            foreach (var role in roles)
            {
                _host.BusyText = $"Đang gỡ role ({++index}/{roles.Count}): {role.Name}";
                try
                {
                    await service.RemoveRoleAsync(isTeam: true, analysis.Team.Id, role.AssignedRoleId, analysis.Team.Name, role.Name);
                }
                catch (Exception ex)
                {
                    errors.Add($"{role.Name}: {ex.Message}");
                }
            }

            if (errors.Count > 0)
                Dialogs.ShowWarning("Một số role không gỡ được:\n\n" + string.Join("\n", errors));
            _host.StatusText = $"Đã gỡ {roles.Count - errors.Count}/{roles.Count} role khỏi team \"{analysis.Team.Name}\".";
        });
        await LoadTeamAsync(analysis.Team);
    }

    [RelayCommand(CanExecute = nameof(CanAddMembers))]
    private async Task AddMembersAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var existing = analysis.Members.Select(m => m.Id).ToHashSet();
        var picked = PrincipalPickerWindow.Show(
            App.Current.MainWindow,
            $"Thêm thành viên vào team \"{analysis.Team.Name}\"",
            async (text, top) => (await service.SearchUsersAsync(text, top)).Where(u => !existing.Contains(u.Id)).ToList(),
            actionText: "Thêm vào team",
            hint: "Nhập tên hoặc username rồi nhấn Enter. Tick nhiều user để thêm cùng lúc.");
        if (picked is null || picked.Count == 0)
            return;

        await _host.RunBusyAsync($"Đang thêm {picked.Count} thành viên...", async () =>
        {
            await service.AddTeamMembersAsync(analysis.Team.Id, picked.Select(p => p.Id), analysis.Team.Name, string.Join(", ", picked.Select(p => p.Name)));
            _host.StatusText = $"Đã thêm {picked.Count} thành viên vào team \"{analysis.Team.Name}\".";
        });
        await LoadTeamAsync(analysis.Team);
    }

    [RelayCommand(CanExecute = nameof(CanRemoveMembers))]
    private async Task RemoveMembersAsync()
    {
        if (_host.Service is not { } service || Analysis is not { } analysis)
            return;

        var members = PickedMembers;
        if (!Dialogs.Confirm($"Gỡ {members.Count} thành viên khỏi team \"{analysis.Team.Name}\"?\n\n{Bullets(members.Select(m => m.FullName))}"))
            return;

        await _host.RunBusyAsync($"Đang gỡ {members.Count} thành viên...", async () =>
        {
            await service.RemoveTeamMembersAsync(analysis.Team.Id, members.Select(m => m.Id), analysis.Team.Name, string.Join(", ", members.Select(m => m.FullName)));
            _host.StatusText = $"Đã gỡ {members.Count} thành viên khỏi team \"{analysis.Team.Name}\".";
        });
        await LoadTeamAsync(analysis.Team);
    }

    private static string Bullets(IEnumerable<string> names)
    {
        var list = names.ToList();
        var text = string.Join("\n", list.Take(15).Select(n => "• " + n));
        return list.Count > 15 ? text + $"\n... và {list.Count - 15} mục khác" : text;
    }

    #endregion

    #region Other commands

    [RelayCommand]
    private void OpenMember(TeamMember? member)
    {
        if (member is not null)
            _ = _host.OpenUserAsync(member.Id);
    }

    [RelayCommand]
    private void OpenRole(TeamRoleAssignment? role)
    {
        if (role is not null)
            _host.OpenRole(role.RootRoleId);
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void Export()
    {
        if (Analysis is null)
            return;

        var path = Dialogs.SaveExcel($"Team_{MainViewModel.SafeFileName(Analysis.Team.Name)}_{DateTime.Now:yyyyMMdd_HHmm}.xlsx");
        if (path is null)
            return;

        try
        {
            ExcelExporter.ExportTeamAnalysis(Analysis, path);
            _host.StatusText = "Đã xuất: " + path;
            if (Dialogs.Confirm("Xuất Excel thành công. Mở file ngay?"))
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Dialogs.ShowError(ex);
        }
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void OpenInBrowser()
    {
        if (_host.Service is null || Analysis is null)
            return;
        _host.OpenRecord("team", Analysis.Team.Id);
    }

    /// <summary>Dữ liệu mẫu cho chế độ --demo.</summary>
    public void LoadDemo(List<TeamInfo> teams, TeamAnalysis analysis)
    {
        SetTeams(teams);
        IsLoaded = true;
        SetSelectedTeamSilently(teams.First(t => t.Id == analysis.Team.Id));
        ApplyAnalysis(analysis);
    }

    #endregion

    partial void OnAnalysisChanged(TeamAnalysis? value)
    {
        OnPropertyChanged(nameof(CanManageMembers));
        AddMembersCommand.NotifyCanExecuteChanged();
        RemoveMembersCommand.NotifyCanExecuteChanged();
    }
}
