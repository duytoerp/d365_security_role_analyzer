using System.Collections;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.ViewModels;

/// <summary>Nền cho ViewModel của cửa sổ công cụ: trạng thái bận riêng của cửa sổ.</summary>
public abstract partial class ToolViewModelBase(MainViewModel host) : ObservableObject
{
    protected MainViewModel Host { get; } = host;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _busyText = "";
    [ObservableProperty] private string _statusText = "";

    /// <summary>Phần trăm hoàn thành (0–100); -1 khi không đo được.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProgressValue), nameof(ProgressText))]
    private double _busyProgress = -1;

    public bool HasProgressValue => BusyProgress >= 0;
    public string ProgressText => BusyProgress >= 0 ? $"{BusyProgress:0}%" : "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    private bool _canCancel;

    private CancellationTokenSource? _cts;

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private void Cancel()
    {
        BusyText = "Đang hủy...";
        CanCancel = false;
        _cts?.Cancel();
    }

    protected async Task RunAsync(string text, Func<Task> action)
    {
        IsBusy = true;
        BusyText = text;
        try
        {
            await action();
        }
        catch (OperationCanceledException)
        {
            StatusText = "Đã hủy thao tác.";
        }
        catch (Exception ex)
        {
            StatusText = "Lỗi: " + ex.Message;
            Dialogs.ShowError(ex, text);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Chạy tác vụ dài có thể hủy, kèm báo phần trăm.</summary>
    protected async Task RunCancellableAsync(string text, Func<CancellationToken, IProgress<(string Text, double Percent)>, Task> action)
    {
        using var cts = new CancellationTokenSource();
        _cts = cts;
        CanCancel = true;
        BusyProgress = 0;

        var progress = new Progress<(string Text, double Percent)>(update =>
        {
            if (!string.IsNullOrEmpty(update.Text))
                BusyText = update.Text;
            BusyProgress = update.Percent;
        });

        try
        {
            await RunAsync(text, () => action(cts.Token, progress));
        }
        finally
        {
            _cts = null;
            CanCancel = false;
            BusyProgress = -1;
        }
    }

    protected IProgress<string> Progress => new Progress<string>(t => BusyText = t);

    protected DataverseService RequireService() =>
        Host.Service ?? throw new InvalidOperationException("Chưa kết nối Dynamics 365.");
}

public sealed record PrivilegeOption(PrivilegeDefinition Privilege, string EntityDisplayName)
{
    public string RightText => Privilege.EntityLogicalName is null ? "Quyền khác" : Privilege.AccessRight.ToString();
    public string Display => Privilege.EntityLogicalName is null ? Privilege.Name : $"{EntityDisplayName} – {Privilege.AccessRight}";
}

#region Lookup

/// <summary>Tra ngược: ai có quyền X trên entity Y ở mức tối thiểu Z.</summary>
public sealed partial class LookupViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    private AccessIndex? _index;

    public ObservableCollection<PrivilegeOption> Privileges { get; } = [];
    public ICollectionView PrivilegesView => field ??= CreatePrivilegesView();
    public IReadOnlyList<PrivilegeDepth> Depths { get; } = [PrivilegeDepth.User, PrivilegeDepth.BusinessUnit, PrivilegeDepth.ParentChild, PrivilegeDepth.Organization];

    [ObservableProperty] private string _privilegeSearchText = "";
    [ObservableProperty] private PrivilegeOption? _selectedPrivilege;
    [ObservableProperty] private PrivilegeDepth _minimumDepth = PrivilegeDepth.User;
    [ObservableProperty] private bool _hideDisabledUsers = true;

    [ObservableProperty] private ICollectionView? _rolesView;
    [ObservableProperty] private ICollectionView? _teamsView;
    [ObservableProperty] private ICollectionView? _usersView;
    private List<LookupRoleRow> _roles = [];
    private List<PrincipalAccessRow> _teams = [];
    private List<PrincipalAccessRow> _users = [];

    [ObservableProperty] private string _roleFilterText = "";
    [ObservableProperty] private string _teamFilterText = "";
    [ObservableProperty] private string _userFilterText = "";

    partial void OnRoleFilterTextChanged(string value) => RolesView?.Refresh();
    partial void OnTeamFilterTextChanged(string value) => TeamsView?.Refresh();
    partial void OnUserFilterTextChanged(string value) => UsersView?.Refresh();

    public string ResultTitle => SelectedPrivilege is null
        ? "Chọn một privilege ở danh sách bên trái"
        : $"{SelectedPrivilege.Privilege.Name}  ·  mức tối thiểu {MinimumDepth.ToText()}: {_roles.Count} role · {_teams.Count} team · {_users.Count(u => !u.IsDisabled)} user";

    private ICollectionView CreatePrivilegesView()
    {
        var view = CollectionViewSource.GetDefaultView(Privileges);
        view.Filter = o => o is PrivilegeOption p
                           && (MainViewModel.Contains(p.Display, PrivilegeSearchText)
                               || MainViewModel.Contains(p.Privilege.Name, PrivilegeSearchText)
                               || MainViewModel.Contains(p.Privilege.EntityLogicalName, PrivilegeSearchText));
        return view;
    }

    partial void OnPrivilegeSearchTextChanged(string value) => PrivilegesView.Refresh();
    partial void OnSelectedPrivilegeChanged(PrivilegeOption? value) => Search();
    partial void OnMinimumDepthChanged(PrivilegeDepth value) => Search();
    partial void OnHideDisabledUsersChanged(bool value) => UsersView?.Refresh();

    [RelayCommand]
    public async Task LoadAsync()
    {
        await RunAsync("Đang tải chỉ mục phân quyền...", async () =>
        {
            var service = RequireService();
            var catalog = await service.GetPrivilegeCatalogAsync();
            var metadata = await service.GetEntityMetadataAsync();
            _index = await service.GetAccessIndexAsync(Progress);

            Privileges.Clear();
            foreach (var option in catalog
                         .Select(p => new PrivilegeOption(p, p.EntityLogicalName is { } e ? metadata.GetValueOrDefault(e)?.DisplayName ?? e : ""))
                         .OrderBy(p => p.Privilege.EntityLogicalName is null)
                         .ThenBy(p => p.Display))
            {
                Privileges.Add(option);
            }
            StatusText = $"Chỉ mục: {_index.Roles.Count} role, {_index.Users.Count} user, {_index.Teams.Count} team (tải lúc {_index.LoadedOn:HH:mm}).";
        });
    }

    private void Search()
    {
        if (_index is null || SelectedPrivilege is null)
            return;
        var (roles, teams, users) = AccessLookup.Find(_index, SelectedPrivilege.Privilege, MinimumDepth);
        _roles = roles;
        _teams = teams;
        _users = users;
        RolesView = new ListCollectionView(roles)
        {
            Filter = o => o is LookupRoleRow r && MainViewModel.Contains(r.Name, RoleFilterText),
        };
        TeamsView = new ListCollectionView(teams)
        {
            Filter = o => o is PrincipalAccessRow t && (MainViewModel.Contains(t.Name, TeamFilterText)
                || MainViewModel.Contains(t.Detail, TeamFilterText) || MainViewModel.Contains(t.Via, TeamFilterText)),
        };
        UsersView = new ListCollectionView(users)
        {
            Filter = o => o is PrincipalAccessRow u && (!HideDisabledUsers || !u.IsDisabled)
                && (MainViewModel.Contains(u.Name, UserFilterText) || MainViewModel.Contains(u.Detail, UserFilterText)
                    || MainViewModel.Contains(u.Via, UserFilterText)),
        };
        OnPropertyChanged(nameof(ResultTitle));
        ExportCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private void OpenRole(LookupRoleRow? role)
    {
        if (role is not null)
            Host.OpenRole(role.RoleId);
    }

    [RelayCommand]
    private void OpenPrincipal(PrincipalAccessRow? row)
    {
        if (row is null)
            return;
        if (row.Type == "Team")
            Host.OpenTeam(row.Id);
        else
            _ = Host.OpenUserAsync(row.Id);
    }

    private bool CanExport => SelectedPrivilege is not null;

    [RelayCommand(CanExecute = nameof(CanExport))]
    private void Export()
    {
        if (SelectedPrivilege is null)
            return;
        Host.ExportWorkbook($"TraCuu_{SelectedPrivilege.Privilege.Name}", wb =>
        {
            ExcelExporter.AddSheet(wb, "Roles", _roles,
                new ExportColumn<LookupRoleRow>("Role", r => r.Name),
                new ExportColumn<LookupRoleRow>("Mức", r => r.DepthText),
                new ExportColumn<LookupRoleRow>("User trực tiếp", r => r.DirectUserCount),
                new ExportColumn<LookupRoleRow>("Team", r => r.TeamCount),
                new ExportColumn<LookupRoleRow>("Managed", r => r.ManagedText));
            ExcelExporter.AddPrincipalSheet(wb, "Teams", _teams);
            ExcelExporter.AddPrincipalSheet(wb, "Users", _users);
        });
    }
}

#endregion

#region Access review

public sealed partial class AccessReviewViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    private AccessIndex? _index;
    private List<ReviewUserRow> _users = [];
    private List<ReviewRoleRow> _roles = [];

    [ObservableProperty] private ICollectionView? _usersView;
    [ObservableProperty] private ICollectionView? _rolesView;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private bool _onlyIssues;
    [ObservableProperty] private bool _onlySystemAdministrators;
    [ObservableProperty] private bool _hideDisabled = true;
    [ObservableProperty] private bool _onlyUnusedRoles;

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];

    partial void OnSearchTextChanged(string value) => RefreshViews();
    partial void OnOnlyIssuesChanged(bool value) => RefreshViews();
    partial void OnOnlySystemAdministratorsChanged(bool value) => RefreshViews();
    partial void OnHideDisabledChanged(bool value) => RefreshViews();
    partial void OnOnlyUnusedRolesChanged(bool value) => RefreshViews();

    private void RefreshViews()
    {
        UsersView?.Refresh();
        RolesView?.Refresh();
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        await RunAsync("Đang tải chỉ mục phân quyền...", async () =>
        {
            _index = await RequireService().GetAccessIndexAsync(Progress);
            (_users, _roles) = AccessReviewBuilder.Build(_index);

            UsersView = new ListCollectionView(_users)
            {
                Filter = o => o is ReviewUserRow r
                              && (!HideDisabled || !r.User.IsDisabled || r.DirectRoleCount > 0)
                              && (!OnlyIssues || r.HasIssue)
                              && (!OnlySystemAdministrators || r.IsSystemAdministrator)
                              && (MainViewModel.Contains(r.User.FullName, SearchText) || MainViewModel.Contains(r.User.DomainName, SearchText)
                                  || MainViewModel.Contains(r.DirectRoles, SearchText) || MainViewModel.Contains(r.TeamRoles, SearchText)
                                  || MainViewModel.Contains(r.User.BusinessUnitName, SearchText)),
            };
            RolesView = new ListCollectionView(_roles)
            {
                Filter = o => o is ReviewRoleRow r && (!OnlyUnusedRoles || r.IsUnused) && MainViewModel.Contains(r.Role.Name, SearchText),
            };

            SummaryCards.Clear();
            var active = _users.Where(u => !u.User.IsDisabled).ToList();
            SummaryCards.Add(new SummaryCard("User đang hoạt động", active.Count.ToString(), $"{_users.Count - active.Count} disabled"));
            SummaryCards.Add(new SummaryCard("Không có role", active.Count(u => u.EffectiveRoleCount == 0).ToString(), "user hoạt động"));
            SummaryCards.Add(new SummaryCard("System Administrator", _users.Count(u => u.IsSystemAdministrator && !u.User.IsDisabled).ToString(), "user hoạt động"));
            SummaryCards.Add(new SummaryCard("Disabled còn role", _users.Count(u => u.User.IsDisabled && u.DirectRoleCount > 0).ToString(), "nên dọn dẹp"));
            SummaryCards.Add(new SummaryCard("Role không dùng", _roles.Count(r => r.IsUnused).ToString(), $"trên {_roles.Count} role"));
            StatusText = $"Chỉ mục tải lúc {_index.LoadedOn:HH:mm:ss}.";
            ExportCommand.NotifyCanExecuteChanged();
        });
    }

    [RelayCommand]
    private void OpenUser(ReviewUserRow? row)
    {
        if (row is not null)
            _ = Host.OpenUserAsync(row.User.Id);
    }

    [RelayCommand]
    private void OpenRole(ReviewRoleRow? row)
    {
        if (row is not null)
            Host.OpenRole(row.Role.Id);
    }

    private bool CanExport => _index is not null;

    [RelayCommand(CanExecute = nameof(CanExport))]
    private void Export()
    {
        if (_index is not { } index)
            return;
        Host.ExportWorkbook("RaSoatQuyen", wb =>
        {
            ExcelExporter.AddSheet(wb, "Users", _users,
                new ExportColumn<ReviewUserRow>("Họ tên", r => r.User.FullName),
                new ExportColumn<ReviewUserRow>("Username", r => r.User.DomainName),
                new ExportColumn<ReviewUserRow>("Business Unit", r => r.User.BusinessUnitName),
                new ExportColumn<ReviewUserRow>("Trạng thái", r => r.User.StatusText),
                new ExportColumn<ReviewUserRow>("Role trực tiếp", r => r.DirectRoles, 60),
                new ExportColumn<ReviewUserRow>("Role qua team", r => r.TeamRoles, 60),
                new ExportColumn<ReviewUserRow>("Số role hiệu lực", r => r.EffectiveRoleCount),
                new ExportColumn<ReviewUserRow>("Cảnh báo", r => r.Flags, 40));
            ExcelExporter.AddSheet(wb, "Roles", _roles,
                new ExportColumn<ReviewRoleRow>("Role", r => r.Role.Name),
                new ExportColumn<ReviewRoleRow>("Managed", r => r.Role.ManagedText),
                new ExportColumn<ReviewRoleRow>("User trực tiếp", r => r.DirectUserCount),
                new ExportColumn<ReviewRoleRow>("Team", r => r.TeamCount),
                new ExportColumn<ReviewRoleRow>("User hiệu lực", r => r.EffectiveUserCount),
                new ExportColumn<ReviewRoleRow>("Không dùng", r => r.IsUnused ? "Yes" : ""));
            ExcelExporter.AddUserRoleMatrix(wb, "Ma tran User x Role", index);
        });
    }
}

#endregion

#region Bulk privileges

public sealed partial class BulkPrivilegeViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    private List<PrivilegeDefinition> _catalog = [];

    public sealed record EntityOption(string LogicalName, string DisplayName)
    {
        public string Display => $"{DisplayName} ({LogicalName})";
    }

    public ObservableCollection<EntityOption> Entities { get; } = [];
    public ObservableCollection<SecurityRoleInfo> Roles { get; } = [];
    public ICollectionView EntitiesView => field ??= CreateView(Entities, o => o is EntityOption e && (MainViewModel.Contains(e.DisplayName, EntitySearchText) || MainViewModel.Contains(e.LogicalName, EntitySearchText)));
    public ICollectionView RolesView => field ??= CreateView(Roles, o => o is SecurityRoleInfo r && (!HideManagedRoles || !r.IsManaged) && MainViewModel.Contains(r.Name, RoleSearchText));

    public IReadOnlyList<PrivilegeDepth> Depths { get; } = [PrivilegeDepth.None, PrivilegeDepth.User, PrivilegeDepth.BusinessUnit, PrivilegeDepth.ParentChild, PrivilegeDepth.Organization];

    [ObservableProperty] private string _entitySearchText = "";
    [ObservableProperty] private string _roleSearchText = "";
    [ObservableProperty] private bool _hideManagedRoles = true;
    [ObservableProperty] private PrivilegeDepth _targetDepth = PrivilegeDepth.Organization;
    [ObservableProperty] private bool _onlyRaise;
    [ObservableProperty] private bool _create;
    [ObservableProperty] private bool _read = true;
    [ObservableProperty] private bool _write;
    [ObservableProperty] private bool _delete;
    [ObservableProperty] private bool _append;
    [ObservableProperty] private bool _appendTo;
    [ObservableProperty] private bool _assign;
    [ObservableProperty] private bool _share;
    [ObservableProperty] private IList? _selectedEntities;
    [ObservableProperty] private IList? _selectedRoles;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ApplyCommand))]
    private List<BulkChangeRow> _preview = [];

    [ObservableProperty] private ICollectionView? _previewView;
    [ObservableProperty] private string _previewFilterText = "";

    partial void OnPreviewFilterTextChanged(string value) => PreviewView?.Refresh();

    partial void OnPreviewChanged(List<BulkChangeRow> value) =>
        PreviewView = new ListCollectionView(value)
        {
            Filter = o => o is BulkChangeRow r && (MainViewModel.Contains(r.RoleName, PreviewFilterText)
                || MainViewModel.Contains(r.Entity, PreviewFilterText) || MainViewModel.Contains(r.PrivilegeName, PreviewFilterText)),
        };

    partial void OnEntitySearchTextChanged(string value) => EntitiesView.Refresh();
    partial void OnRoleSearchTextChanged(string value) => RolesView.Refresh();
    partial void OnHideManagedRolesChanged(bool value) => RolesView.Refresh();

    private static ICollectionView CreateView<T>(ObservableCollection<T> items, Predicate<object> filter)
    {
        var view = new ListCollectionView(items) { Filter = filter };
        return view;
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        await RunAsync("Đang tải entity và role...", async () =>
        {
            var service = RequireService();
            _catalog = await service.GetPrivilegeCatalogAsync();
            var metadata = await service.GetEntityMetadataAsync();
            Entities.Clear();
            foreach (var name in _catalog.Where(p => p.EntityLogicalName is not null).Select(p => p.EntityLogicalName!).Distinct(StringComparer.OrdinalIgnoreCase)
                         .Select(n => new EntityOption(n, metadata.GetValueOrDefault(n)?.DisplayName ?? n)).OrderBy(e => e.DisplayName))
            {
                Entities.Add(name);
            }
            Roles.Clear();
            foreach (var role in Host.Roles)
                Roles.Add(role);
        });
    }

    [RelayCommand]
    private async Task PreviewAsync()
    {
        var entities = SelectedEntities?.OfType<EntityOption>().ToList() ?? [];
        var roles = SelectedRoles?.OfType<SecurityRoleInfo>().ToList() ?? [];
        var rights = new (bool On, AccessRight Right)[]
        {
            (Create, AccessRight.Create), (Read, AccessRight.Read), (Write, AccessRight.Write), (Delete, AccessRight.Delete),
            (Append, AccessRight.Append), (AppendTo, AccessRight.AppendTo), (Assign, AccessRight.Assign), (Share, AccessRight.Share),
        }.Where(r => r.On).Select(r => r.Right).ToList();

        if (entities.Count == 0 || roles.Count == 0 || rights.Count == 0)
        {
            Dialogs.ShowWarning("Hãy chọn ít nhất 1 entity, 1 quyền (Create/Read/...) và 1 role.");
            return;
        }

        await RunAsync("Đang tính toán thay đổi...", async () =>
        {
            var service = RequireService();
            var entityNames = entities.Select(e => e.LogicalName).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var privileges = _catalog.Where(p => p.EntityLogicalName is not null && entityNames.Contains(p.EntityLogicalName) && rights.Contains(p.AccessRight)).ToList();
            var rows = new List<BulkChangeRow>();
            foreach (var role in roles)
            {
                BusyText = $"Đang đọc privilege của \"{role.Name}\"...";
                var current = await service.GetRolePrivilegesAsync(role.Id);
                foreach (var privilege in privileges)
                {
                    var now = current.GetValueOrDefault(privilege.Id);
                    var target = privilege.Clamp(TargetDepth);
                    var note = target != TargetDepth ? $"Privilege không hỗ trợ mức {TargetDepth.ToText()} – dùng {target.ToText()}" : "";
                    if (OnlyRaise && target <= now)
                        continue;
                    if (target == now)
                        continue;
                    rows.Add(new BulkChangeRow
                    {
                        RoleId = role.Id, RoleName = role.Name, PrivilegeId = privilege.Id, PrivilegeName = privilege.Name,
                        Entity = privilege.EntityLogicalName!, Right = privilege.AccessRight.ToString(), Current = now, Target = target, Note = note,
                    });
                }
            }
            Preview = rows.OrderBy(r => r.RoleName).ThenBy(r => r.Entity).ThenBy(r => r.Right).ToList();
            StatusText = $"{Preview.Count} thay đổi trên {Preview.Select(r => r.RoleId).Distinct().Count()} role.";
        });
    }

    private bool CanApply => Preview.Count > 0;

    [RelayCommand(CanExecute = nameof(CanApply))]
    private async Task ApplyAsync()
    {
        var byRole = Preview.GroupBy(r => (r.RoleId, r.RoleName)).ToList();
        if (!Dialogs.Confirm($"Áp dụng {Preview.Count} thay đổi cho {byRole.Count} role?\n\nMỗi role sẽ được sao lưu privilege trước khi sửa (có thể hoàn tác trong Lịch sử thao tác)."))
            return;

        await RunCancellableAsync("Đang áp dụng...", async (ct, progress) =>
        {
            var service = RequireService();
            var definitions = _catalog.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First());
            var errors = new List<string>();
            var done = 0;
            foreach (var group in byRole)
            {
                // Hủy giữa chừng: các role đã xử lý vẫn giữ nguyên thay đổi, đều có bản sao lưu trong Lịch sử.
                ct.ThrowIfCancellationRequested();
                progress.Report(($"Đang cập nhật role {done + 1}/{byRole.Count}: {group.Key.RoleName}", done * 100.0 / byRole.Count));
                try
                {
                    await service.UpdateRolePrivilegesAsync(group.Key.RoleId, group.Key.RoleName,
                        group.Select(r => (definitions[r.PrivilegeId], r.Target)).ToList(), "Áp quyền hàng loạt", ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    errors.Add($"{group.Key.RoleName}: {ex.Message}");
                }
                done++;
            }
            if (errors.Count > 0)
                Dialogs.ShowWarning("Một số role không cập nhật được:\n\n" + string.Join("\n", errors));
            StatusText = $"Đã cập nhật {done - errors.Count}/{byRole.Count} role.";
            Preview = [];
        });
    }
}

#endregion

#region Snapshot

public sealed partial class SnapshotViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    public const string AllText = "Tất cả";

    [ObservableProperty] private EnvironmentSnapshot? _snapshotA;
    [ObservableProperty] private EnvironmentSnapshot? _snapshotB;
    [ObservableProperty] private ICollectionView? _diffView;
    [ObservableProperty] private string _categoryFilter = AllText;
    [ObservableProperty] private string _changeFilter = AllText;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private IList? _selectedRows;
    private List<SnapshotDiffRow> _rows = [];

    public IReadOnlyList<string> Categories { get; } =
        [AllText, SnapshotService.CategoryRole, SnapshotService.CategoryPrivilege, SnapshotService.CategoryUserRole, SnapshotService.CategoryTeamRole, SnapshotService.CategoryTeamMember];

    public IReadOnlyList<string> ChangeTypes { get; } = [AllText, SnapshotService.Added, SnapshotService.Removed, SnapshotService.Changed];

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];

    public string SnapshotAText => SnapshotA?.Title ?? "(chưa chọn)";
    public string SnapshotBText => SnapshotB?.Title ?? "(chưa chọn)";

    partial void OnSnapshotAChanged(EnvironmentSnapshot? value) => OnPropertyChanged(nameof(SnapshotAText));
    partial void OnSnapshotBChanged(EnvironmentSnapshot? value) => OnPropertyChanged(nameof(SnapshotBText));
    partial void OnCategoryFilterChanged(string value) => DiffView?.Refresh();
    partial void OnChangeFilterChanged(string value) => DiffView?.Refresh();
    partial void OnSearchTextChanged(string value) => DiffView?.Refresh();

    private async Task<EnvironmentSnapshot> CaptureAsync()
    {
        var service = RequireService();
        var catalog = await service.GetPrivilegeCatalogAsync();
        service.ClearCache();
        var index = await service.GetAccessIndexAsync(Progress);
        return SnapshotService.Create(index, catalog, service.EnvironmentKey, service.CurrentUserName);
    }

    [RelayCommand]
    private async Task CaptureAndSaveAsync()
    {
        if (Host.Service is null)
        {
            Dialogs.ShowWarning("Hãy kết nối môi trường trước khi chụp snapshot.");
            return;
        }
        await RunAsync("Đang chụp snapshot môi trường...", async () =>
        {
            var snapshot = await CaptureAsync();
            var dialog = new SaveFileDialog
            {
                FileName = $"Snapshot_{snapshot.Environment}_{DateTime.Now:yyyyMMdd_HHmm}.json",
                Filter = "Snapshot (*.json)|*.json",
                InitialDirectory = SnapshotFolder(),
            };
            if (dialog.ShowDialog() != true)
                return;
            SnapshotService.Save(snapshot, dialog.FileName);
            StatusText = $"Đã lưu snapshot: {dialog.FileName} ({snapshot.Roles.Count} role, {snapshot.UserRoles.Count} gán role user).";
        });
    }

    [RelayCommand]
    private Task UseCurrentForAAsync() => RunAsync("Đang chụp môi trường hiện tại...", async () => SnapshotA = await CaptureAsync());

    [RelayCommand]
    private Task UseCurrentForBAsync() => RunAsync("Đang chụp môi trường hiện tại...", async () => SnapshotB = await CaptureAsync());

    [RelayCommand]
    private void LoadA()
    {
        if (PickFile() is { } snapshot)
            SnapshotA = snapshot;
    }

    [RelayCommand]
    private void LoadB()
    {
        if (PickFile() is { } snapshot)
            SnapshotB = snapshot;
    }

    private static string SnapshotFolder()
    {
        var folder = Path.Combine(ConnectionProfileStore.AppDataFolder, "Snapshots");
        Directory.CreateDirectory(folder);
        return folder;
    }

    private static EnvironmentSnapshot? PickFile()
    {
        var dialog = new OpenFileDialog { Filter = "Snapshot (*.json)|*.json", InitialDirectory = SnapshotFolder() };
        if (dialog.ShowDialog() != true)
            return null;
        try
        {
            return SnapshotService.Load(dialog.FileName);
        }
        catch (Exception ex)
        {
            Dialogs.ShowError(ex);
            return null;
        }
    }

    [RelayCommand]
    private void Compare()
    {
        if (SnapshotA is null || SnapshotB is null)
        {
            Dialogs.ShowWarning("Hãy chọn đủ snapshot A (trước) và B (sau).");
            return;
        }

        _rows = SnapshotService.Compare(SnapshotA, SnapshotB);
        DiffView = new ListCollectionView(_rows)
        {
            Filter = o => o is SnapshotDiffRow r
                          && (CategoryFilter == AllText || r.Category == CategoryFilter)
                          && (ChangeFilter == AllText || r.ChangeType == ChangeFilter)
                          && (MainViewModel.Contains(r.Item, SearchText) || MainViewModel.Contains(r.Detail, SearchText)),
        };

        SummaryCards.Clear();
        foreach (var category in Categories.Skip(1))
        {
            var items = _rows.Where(r => r.Category == category).ToList();
            SummaryCards.Add(new SummaryCard(category, items.Count.ToString(),
                $"+{items.Count(r => r.ChangeType == SnapshotService.Added)}  −{items.Count(r => r.ChangeType == SnapshotService.Removed)}  ~{items.Count(r => r.ChangeType == SnapshotService.Changed)}"));
        }
        StatusText = $"{_rows.Count} khác biệt giữa \"{SnapshotA.Title}\" và \"{SnapshotB.Title}\".";
        ExportCommand.NotifyCanExecuteChanged();
        ApplyCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(ApplyHint));
    }

    /// <summary>Số dòng áp được sang môi trường đang kết nối (chỉ privilege của role).</summary>
    public int ApplicableCount => _rows.Count(r => r.CanApply);

    public string ApplyHint => _rows.Count == 0
        ? ""
        : $"Áp sang môi trường đang kết nối: {ApplicableCount}/{_rows.Count} khác biệt (privilege của role). "
          + "Gán role cho user/team và thành viên team dùng công cụ Import.";

    private bool CanApply => _rows.Any(r => r.CanApply) && Host.Service is not null;

    /// <summary>Đưa privilege của role trên môi trường đang kết nối về đúng như snapshot B.</summary>
    [RelayCommand(CanExecute = nameof(CanApply))]
    private async Task ApplyAsync()
    {
        if (SnapshotB is not { } source || Host.Service is not { } service)
            return;

        // Không tick dòng nào nghĩa là áp toàn bộ khác biệt áp được.
        var selected = SelectedRows?.OfType<SnapshotDiffRow>().Where(r => r.CanApply).ToList() ?? [];
        if (selected.Count == 0)
            selected = _rows.Where(r => r.CanApply).ToList();

        var roleCount = selected.Select(r => r.Item).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (!Dialogs.Confirm(
                $"Áp {selected.Count} thay đổi privilege lên {roleCount} role của môi trường \"{service.EnvironmentKey}\","
                + $"\nlấy theo bản B \"{source.Title}\"?"
                + "\n\nPrivilege của mỗi role được sao lưu trước khi sửa (hoàn tác được trong Lịch sử thao tác)."))
        {
            return;
        }

        await RunCancellableAsync("Đang áp diff snapshot...", async (ct, progress) =>
        {
            var result = await SnapshotApplyService.ApplyAsync(service, source, selected, progress, ct);
            StatusText = result.Summary;

            if (result.Errors.Count > 0 || result.Skipped.Count > 0)
            {
                var detail = result.Errors.Count > 0 ? "Lỗi:\n" + string.Join("\n", result.Errors.Take(20)) : "";
                if (result.Skipped.Count > 0)
                    detail += (detail.Length > 0 ? "\n\n" : "") + "Bỏ qua:\n" + string.Join("\n", result.Skipped.Take(20));
                Dialogs.ShowWarning(detail);
            }
        });
    }

    private bool CanExport => _rows.Count > 0;

    [RelayCommand(CanExecute = nameof(CanExport))]
    private void Export() =>
        Host.ExportWorkbook("SoSanhSnapshot", wb =>
        {
            ExcelExporter.AddInfoSheet(wb, "Tong quan", [("A (trước)", SnapshotAText), ("B (sau)", SnapshotBText), ("Số khác biệt", _rows.Count)], []);
            ExcelExporter.AddSheet(wb, "Khac biet", _rows,
                new ExportColumn<SnapshotDiffRow>("Loại", r => r.Category),
                new ExportColumn<SnapshotDiffRow>("Thay đổi", r => r.ChangeType),
                new ExportColumn<SnapshotDiffRow>("Đối tượng", r => r.Item, 40),
                new ExportColumn<SnapshotDiffRow>("Chi tiết", r => r.Detail, 40),
                new ExportColumn<SnapshotDiffRow>("A (trước)", r => r.Before),
                new ExportColumn<SnapshotDiffRow>("B (sau)", r => r.After));
        });
}

#endregion

#region Import

public sealed partial class ImportViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    [ObservableProperty] private string _filePath = "";
    [ObservableProperty] private ICollectionView? _rowsView;
    [ObservableProperty] private bool _onlyProblems;
    private List<ImportRow> _rows = [];

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];

    partial void OnOnlyProblemsChanged(bool value) => RowsView?.Refresh();

    [RelayCommand]
    private void CreateTemplate()
    {
        var dialog = new SaveFileDialog { FileName = "MauImportPhanQuyen.xlsx", Filter = "Excel (*.xlsx)|*.xlsx" };
        if (dialog.ShowDialog() != true)
            return;
        ImportService.CreateTemplate(dialog.FileName);
        Process.Start(new ProcessStartInfo(dialog.FileName) { UseShellExecute = true });
    }

    [RelayCommand]
    private async Task OpenFileAsync()
    {
        var dialog = new OpenFileDialog { Filter = "Excel / CSV (*.xlsx;*.csv)|*.xlsx;*.csv" };
        if (dialog.ShowDialog() != true)
            return;
        FilePath = dialog.FileName;

        await RunAsync("Đang đọc và kiểm tra file...", async () =>
        {
            _rows = ImportService.Read(FilePath);
            var index = await RequireService().GetAccessIndexAsync(Progress);
            ImportService.Resolve(_rows, index);
            RowsView = new ListCollectionView(_rows) { Filter = o => o is ImportRow r && (!OnlyProblems || r.Status is ImportStatus.Error or ImportStatus.Failed) };
            UpdateSummary();
            ExecuteCommand.NotifyCanExecuteChanged();
        });
    }

    private void UpdateSummary()
    {
        SummaryCards.Clear();
        SummaryCards.Add(new SummaryCard("Tổng dòng", _rows.Count.ToString(), Path.GetFileName(FilePath)));
        SummaryCards.Add(new SummaryCard(ImportStatus.Valid, _rows.Count(r => r.Status == ImportStatus.Valid).ToString(), "sẽ được thực hiện"));
        SummaryCards.Add(new SummaryCard(ImportStatus.Skipped, _rows.Count(r => r.Status == ImportStatus.Skipped).ToString(), "không cần thay đổi"));
        SummaryCards.Add(new SummaryCard(ImportStatus.Error, _rows.Count(r => r.Status == ImportStatus.Error).ToString(), "cần sửa file"));
        SummaryCards.Add(new SummaryCard(ImportStatus.Done, _rows.Count(r => r.Status == ImportStatus.Done).ToString(), $"{_rows.Count(r => r.Status == ImportStatus.Failed)} thất bại"));
    }

    private bool CanExecute => _rows.Any(r => r.IsValid);

    [RelayCommand(CanExecute = nameof(CanExecute))]
    private async Task ExecuteAsync()
    {
        var valid = _rows.Where(r => r.IsValid).ToList();
        if (!Dialogs.Confirm($"Thực hiện {valid.Count} thao tác trên môi trường \"{Host.Service?.EnvironmentKey}\"?"))
            return;

        await RunCancellableAsync("Đang thực hiện...", async (ct, progress) =>
        {
            var service = RequireService();
            var cancelled = false;
            for (var i = 0; i < valid.Count; i++)
            {
                if (ct.IsCancellationRequested)
                {
                    cancelled = true;
                    break;
                }

                var row = valid[i];
                progress.Report(($"Dòng {row.RowNumber} ({i + 1}/{valid.Count}): {row.Action} {row.Target} – {row.PrincipalDisplay}",
                    i * 100.0 / valid.Count));
                try
                {
                    await ImportService.ExecuteAsync(row, service, ct);
                    row.Status = ImportStatus.Done;
                    row.Message = "";
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    row.Status = ImportStatus.Failed;
                    row.Message = ex.Message;
                }
            }

            RowsView?.Refresh();
            UpdateSummary();
            var done = valid.Count(r => r.Status == ImportStatus.Done);
            var failed = valid.Count(r => r.Status == ImportStatus.Failed);
            StatusText = cancelled
                ? $"Đã hủy sau {done + failed}/{valid.Count} dòng: {done} thành công, {failed} thất bại. Các dòng còn lại giữ nguyên."
                : $"Hoàn tất: {done} thành công, {failed} thất bại.";
            ExecuteCommand.NotifyCanExecuteChanged();
        });
    }

    [RelayCommand]
    private void ExportResults()
    {
        if (_rows.Count == 0)
            return;
        Host.ExportWorkbook("KetQuaImport", wb => ExcelExporter.AddSheet(wb, "Ket qua", _rows,
            new ExportColumn<ImportRow>("Dòng", r => r.RowNumber),
            new ExportColumn<ImportRow>("Loại", r => r.PrincipalType),
            new ExportColumn<ImportRow>("Principal", r => r.Principal),
            new ExportColumn<ImportRow>("Hành động", r => r.Action),
            new ExportColumn<ImportRow>("Đối tượng", r => r.Target),
            new ExportColumn<ImportRow>("Trạng thái", r => r.Status),
            new ExportColumn<ImportRow>("Ghi chú", r => r.Message, 60)));
    }
}

#endregion

#region History

public sealed partial class HistoryViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    [ObservableProperty] private ICollectionView? _entriesView;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private bool _onlyCurrentEnvironment = true;
    [ObservableProperty] private bool _onlyErrors;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(UndoCommand))]
    private ActionLogEntry? _selectedEntry;

    partial void OnSearchTextChanged(string value) => EntriesView?.Refresh();
    partial void OnOnlyCurrentEnvironmentChanged(bool value) => EntriesView?.Refresh();
    partial void OnOnlyErrorsChanged(bool value) => EntriesView?.Refresh();

    public string CurrentEnvironment => Host.Service?.EnvironmentKey ?? "(chưa kết nối)";

    [RelayCommand]
    public void Load()
    {
        var entries = ActionLogStore.Load();
        EntriesView = new ListCollectionView(entries)
        {
            Filter = o => o is ActionLogEntry e
                          && (!OnlyCurrentEnvironment || Host.Service is null || string.Equals(e.Environment, Host.Service.EnvironmentKey, StringComparison.OrdinalIgnoreCase))
                          && (!OnlyErrors || !e.Success)
                          && (MainViewModel.Contains(e.Action, SearchText) || MainViewModel.Contains(e.Target, SearchText)
                              || MainViewModel.Contains(e.Detail, SearchText) || MainViewModel.Contains(e.Operator, SearchText)),
        };
        StatusText = $"{entries.Count} mục – lưu tại {ActionLogStore.FilePath}";
    }

    private bool CanUndo => SelectedEntry is { CanUndo: true } && Host.Service is not null;

    [RelayCommand(CanExecute = nameof(CanUndo))]
    private async Task UndoAsync()
    {
        if (SelectedEntry is not { } entry)
            return;
        if (!Dialogs.Confirm($"Hoàn tác thao tác sau?\n\n{entry.Action}\n{entry.Target}\n{entry.Detail}"))
            return;

        await RunAsync("Đang hoàn tác...", async () =>
        {
            await RequireService().UndoAsync(entry);
            StatusText = "Đã hoàn tác: " + entry.Action;
            Load();
        });
    }

    [RelayCommand]
    private static void OpenFolder() =>
        Process.Start(new ProcessStartInfo(ConnectionProfileStore.AppDataFolder) { UseShellExecute = true });
}

#endregion

#region Role trùng lặp

/// <summary>Tìm các cặp role có privilege chồng lấn nhiều để gộp hoặc dọn bớt.</summary>
public sealed partial class RoleOverlapViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    [ObservableProperty] private ICollectionView? _rowsView;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private bool _onlySubsets;

    /// <summary>Ngưỡng trùng lặp tối thiểu, phần trăm.</summary>
    [ObservableProperty] private int _minimumSimilarity = 90;

    private List<RoleOverlapRow> _rows = [];

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];

    public IReadOnlyList<int> SimilarityOptions { get; } = [100, 95, 90, 80, 70, 60, 50];

    partial void OnSearchTextChanged(string value) => RowsView?.Refresh();
    partial void OnOnlySubsetsChanged(bool value) => RowsView?.Refresh();

    [RelayCommand]
    public async Task LoadAsync()
    {
        await RunAsync("Đang so sánh privilege của tất cả role...", async () =>
        {
            var service = RequireService();
            var index = await service.GetAccessIndexAsync(Progress);
            _rows = RoleOverlapAnalyzer.Find(index, MinimumSimilarity / 100.0);

            RowsView = new ListCollectionView(_rows)
            {
                Filter = o => o is RoleOverlapRow r
                              && (!OnlySubsets || r.IsSubset)
                              && (MainViewModel.Contains(r.NameA, SearchText) || MainViewModel.Contains(r.NameB, SearchText)),
            };

            SummaryCards.Clear();
            SummaryCards.Add(new SummaryCard("Cặp trùng lặp", _rows.Count.ToString(), $"từ {MinimumSimilarity}% trở lên"));
            SummaryCards.Add(new SummaryCard("Giống hệt nhau", _rows.Count(r => r.Similarity >= 1).ToString(), "nên giữ một role"));
            SummaryCards.Add(new SummaryCard("Chứa trọn nhau", _rows.Count(r => r.IsSubset).ToString(), "role nhỏ có thể bỏ"));
            SummaryCards.Add(new SummaryCard("Role đã so sánh", index.Roles.Count.ToString(), "có ít nhất 1 privilege"));

            StatusText = _rows.Count == 0
                ? $"Không có cặp role nào trùng nhau từ {MinimumSimilarity}% trở lên."
                : $"{_rows.Count} cặp role trùng nhau từ {MinimumSimilarity}% trở lên.";
            ExportCommand.NotifyCanExecuteChanged();
        });
    }

    [RelayCommand]
    private void OpenRole(object? row)
    {
        if (row is RoleOverlapRow overlap)
            Host.OpenRole(overlap.RoleA.Id);
    }

    private bool CanExport => _rows.Count > 0;

    [RelayCommand(CanExecute = nameof(CanExport))]
    private void Export() =>
        Host.ExportWorkbook("RoleTrungLap", wb => ExcelExporter.AddSheet(wb, "Role trung lap", _rows,
            new ExportColumn<RoleOverlapRow>("Role A", r => r.NameA, 40),
            new ExportColumn<RoleOverlapRow>("Role B", r => r.NameB, 40),
            new ExportColumn<RoleOverlapRow>("Trùng nhau", r => r.SimilarityText),
            new ExportColumn<RoleOverlapRow>("Privilege chung", r => r.SharedCount),
            new ExportColumn<RoleOverlapRow>("Chỉ có ở A", r => r.OnlyInA),
            new ExportColumn<RoleOverlapRow>("Chỉ có ở B", r => r.OnlyInB),
            new ExportColumn<RoleOverlapRow>("User của A", r => r.UsersA),
            new ExportColumn<RoleOverlapRow>("User của B", r => r.UsersB),
            new ExportColumn<RoleOverlapRow>("Gợi ý", r => r.Suggestion, 60)));
}

#endregion

#region Audit log của Dataverse

/// <summary>Xem thay đổi phân quyền lấy từ audit log của chính Dataverse.</summary>
public sealed partial class AuditViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    [ObservableProperty] private ICollectionView? _entriesView;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private int _days = 30;
    [ObservableProperty] private string _notice = "";

    private List<AuditEntry> _entries = [];

    public IReadOnlyList<int> DayOptions { get; } = [7, 30, 90, 180];

    partial void OnSearchTextChanged(string value) => EntriesView?.Refresh();

    [RelayCommand]
    public async Task LoadAsync()
    {
        await RunAsync($"Đang đọc audit log {Days} ngày gần nhất...", async () =>
        {
            var service = RequireService();

            if (!await service.IsAuditEnabledAsync())
            {
                Notice = "⚠ Môi trường này chưa bật Auditing, nên audit log không có dữ liệu. "
                         + "Bật trong Power Platform admin center → Settings → Auditing.";
                _entries = [];
            }
            else
            {
                Notice = "";
                _entries = await service.GetSecurityAuditAsync(Days);
            }

            EntriesView = new ListCollectionView(_entries)
            {
                Filter = o => o is AuditEntry e
                              && (MainViewModel.Contains(e.TargetName, SearchText)
                                  || MainViewModel.Contains(e.UserName, SearchText)
                                  || MainViewModel.Contains(e.Action, SearchText)
                                  || MainViewModel.Contains(e.EntityName, SearchText)),
            };

            StatusText = $"{_entries.Count} thay đổi trong {Days} ngày gần nhất"
                         + (_entries.Count > 0 ? $" (mới nhất: {_entries[0].TimeText})." : ".");
            ExportCommand.NotifyCanExecuteChanged();
        });
    }

    private bool CanExport => _entries.Count > 0;

    [RelayCommand(CanExecute = nameof(CanExport))]
    private void Export() =>
        Host.ExportWorkbook("AuditPhanQuyen", wb => ExcelExporter.AddSheet(wb, "Audit", _entries,
            new ExportColumn<AuditEntry>("Thời gian", e => e.TimeText, 20),
            new ExportColumn<AuditEntry>("Thao tác", e => e.Action, 25),
            new ExportColumn<AuditEntry>("Bảng", e => e.EntityName, 22),
            new ExportColumn<AuditEntry>("Đối tượng", e => e.TargetName, 40),
            new ExportColumn<AuditEntry>("Người thực hiện", e => e.UserName, 30)));
}

#endregion

#region Giải thích quyền trên một bản ghi

/// <summary>Vì sao user X thấy / không thấy bản ghi Y.</summary>
public sealed partial class RecordAccessViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    [ObservableProperty] private string _recordText = "";
    [ObservableProperty] private UserInfo? _user;
    [ObservableProperty] private RecordAccessExplanation? _result;
    [ObservableProperty] private string _hierarchyText = "";
    [ObservableProperty] private string _templatesText = "";

    public bool HasResult => Result is not null;
    public string UserText => User is null ? "(chưa chọn user)" : $"{User.FullName} · {User.DomainName}";

    partial void OnUserChanged(UserInfo? value)
    {
        OnPropertyChanged(nameof(UserText));
        ExplainCommand.NotifyCanExecuteChanged();
    }

    partial void OnRecordTextChanged(string value) => ExplainCommand.NotifyCanExecuteChanged();

    partial void OnResultChanged(RecordAccessExplanation? value) => OnPropertyChanged(nameof(HasResult));

    [RelayCommand]
    public async Task LoadContextAsync()
    {
        await RunAsync("Đang đọc cấu hình bảo mật của môi trường...", async () =>
        {
            var service = RequireService();
            HierarchyText = (await service.GetHierarchySecurityAsync()).Text;

            var templates = await service.GetAccessTeamTemplatesAsync();
            TemplatesText = templates.Count == 0
                ? "Môi trường không dùng access team template."
                : $"{templates.Count} access team template: "
                  + string.Join("; ", templates.Take(6).Select(t => $"{t.Name} ({t.EntityText}) – {t.RightsText}"))
                  + (templates.Count > 6 ? $"; ... (+{templates.Count - 6})" : "");
        });
    }

    [RelayCommand]
    private void PickUser()
    {
        if (Host.Service is not { } service)
            return;

        var picked = PrincipalPickerWindow.Show(App.Current.MainWindow, "Chọn user cần kiểm tra",
            async (text, top) => await service.SearchUsersAsync(text, top),
            actionText: "Chọn user",
            hint: "Chọn đúng 1 user.");
        if (picked is not { Count: 1 })
        {
            if (picked is { Count: > 1 })
                Dialogs.ShowWarning("Vui lòng chọn đúng 1 user.");
            return;
        }

        // Lấy thông tin đầy đủ (Business Unit, trạng thái) từ danh sách user đã tải.
        var id = picked[0].Id;
        User = Host.UserManager.Users.FirstOrDefault(u => u.Id == id)
               ?? new UserInfo
               {
                   Id = id,
                   FullName = picked[0].Name,
                   DomainName = picked[0].Detail,
                   BusinessUnitId = picked[0].BusinessUnitId,
                   BusinessUnitName = picked[0].BusinessUnitName,
               };
    }

    private bool CanExplain => User is not null && !string.IsNullOrWhiteSpace(RecordText);

    [RelayCommand(CanExecute = nameof(CanExplain))]
    private async Task ExplainAsync()
    {
        if (User is not { } user)
            return;

        if (RecordAccessExplainer.ParseRecordReference(RecordText) is not { } reference)
        {
            Dialogs.ShowWarning(
                "Không đọc được bản ghi từ nội dung đã nhập.\n\n"
                + "Dán URL bản ghi từ D365 (có etn= và id=), hoặc nhập theo dạng:\n"
                + "account 00000000-0000-0000-0000-000000000000");
            return;
        }

        await RunAsync("Đang phân tích quyền trên bản ghi...", async () =>
        {
            var service = RequireService();
            Result = await RecordAccessExplainer.ExplainAsync(service, user, reference.Entity, reference.Id, Progress);
            StatusText = Result.Headline + " " + Result.RightsText;
        });
    }

    [RelayCommand]
    private void OpenRecord()
    {
        if (Result is { } result)
            Host.OpenRecord(result.Record.EntityLogicalName, result.Record.RecordId);
    }
}

#endregion
