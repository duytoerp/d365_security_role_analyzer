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

    protected async Task RunAsync(string text, Func<Task> action)
    {
        IsBusy = true;
        BusyText = text;
        try
        {
            await action();
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

    [ObservableProperty] private List<LookupRoleRow> _roles = [];
    [ObservableProperty] private List<PrincipalAccessRow> _teams = [];
    [ObservableProperty] private ICollectionView? _usersView;
    private List<PrincipalAccessRow> _users = [];

    public string ResultTitle => SelectedPrivilege is null
        ? "Chọn một privilege ở danh sách bên trái"
        : $"{SelectedPrivilege.Privilege.Name}  ·  mức tối thiểu {MinimumDepth.ToText()}: {Roles.Count} role · {Teams.Count} team · {_users.Count(u => !u.IsDisabled)} user";

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
        Roles = roles;
        Teams = teams;
        _users = users;
        UsersView = new ListCollectionView(users) { Filter = o => o is PrincipalAccessRow u && (!HideDisabledUsers || !u.IsDisabled) };
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
            ExcelExporter.AddSheet(wb, "Roles", Roles,
                new ExportColumn<LookupRoleRow>("Role", r => r.Name),
                new ExportColumn<LookupRoleRow>("Mức", r => r.DepthText),
                new ExportColumn<LookupRoleRow>("User trực tiếp", r => r.DirectUserCount),
                new ExportColumn<LookupRoleRow>("Team", r => r.TeamCount),
                new ExportColumn<LookupRoleRow>("Managed", r => r.ManagedText));
            ExcelExporter.AddPrincipalSheet(wb, "Teams", Teams);
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

        await RunAsync("Đang áp dụng...", async () =>
        {
            var service = RequireService();
            var definitions = _catalog.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First());
            var errors = new List<string>();
            var index = 0;
            foreach (var group in byRole)
            {
                BusyText = $"Đang cập nhật role {++index}/{byRole.Count}: {group.Key.RoleName}";
                try
                {
                    await service.UpdateRolePrivilegesAsync(group.Key.RoleId, group.Key.RoleName,
                        group.Select(r => (definitions[r.PrivilegeId], r.Target)).ToList(), "Áp quyền hàng loạt");
                }
                catch (Exception ex)
                {
                    errors.Add($"{group.Key.RoleName}: {ex.Message}");
                }
            }
            if (errors.Count > 0)
                Dialogs.ShowWarning("Một số role không cập nhật được:\n\n" + string.Join("\n", errors));
            StatusText = $"Đã cập nhật {byRole.Count - errors.Count}/{byRole.Count} role.";
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

        await RunAsync("Đang thực hiện...", async () =>
        {
            var service = RequireService();
            for (var i = 0; i < valid.Count; i++)
            {
                var row = valid[i];
                BusyText = $"Dòng {row.RowNumber} ({i + 1}/{valid.Count}): {row.Action} {row.Target} – {row.PrincipalDisplay}";
                try
                {
                    await ImportService.ExecuteAsync(row, service);
                    row.Status = ImportStatus.Done;
                    row.Message = "";
                }
                catch (Exception ex)
                {
                    row.Status = ImportStatus.Failed;
                    row.Message = ex.Message;
                }
            }
            RowsView?.Refresh();
            UpdateSummary();
            StatusText = $"Hoàn tất: {valid.Count(r => r.Status == ImportStatus.Done)} thành công, {valid.Count(r => r.Status == ImportStatus.Failed)} thất bại.";
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
