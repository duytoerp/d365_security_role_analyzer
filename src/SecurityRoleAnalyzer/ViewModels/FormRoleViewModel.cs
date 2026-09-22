using System.Collections;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.ViewModels;

/// <summary>Tùy chọn lọc theo một role cụ thể; Id rỗng nghĩa là không lọc.</summary>
public sealed record RoleFilterOption(Guid RoleId, string Name)
{
    public static readonly RoleFilterOption All = new(Guid.Empty, "(tất cả role)");

    public bool IsAll => RoleId == Guid.Empty;

    public override string ToString() => Name;
}

/// <summary>
/// Chiều ngược của tab Components: mỗi form/dashboard đang được mở cho những role nào –
/// đúng màn hình "Form settings → Security roles" của D365.
/// </summary>
public sealed partial class FormRoleViewModel(MainViewModel host) : ToolViewModelBase(host)
{
    public const string AllVisibilities = "(tất cả)";
    private const string OnlySpecific = "Chỉ form gán role cụ thể";
    private const string OnlyEveryone = "Chỉ form mở cho mọi role";
    private const string OnlyUnreadable = "Chỉ form không đọc được cấu hình";
    private const string OnlyNotScoped = "Chỉ form không phân quyền theo role";

    private List<FormRoleRow> _rows = [];
    private RoleDirectory _directory = new();
    private IReadOnlyDictionary<string, EntityInfo>? _metadata;
    private List<ActionLogEntry> _history = [];

    [ObservableProperty] private ICollectionView? _rowsView;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private string _visibilityFilter = AllVisibilities;
    [ObservableProperty] private RoleFilterOption _roleFilter = RoleFilterOption.All;
    [ObservableProperty] private bool _onlyActive = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection), nameof(SelectedTitle), nameof(SelectedSubtitle),
        nameof(SelectedHint), nameof(HintIsWarning), nameof(HintIsInfo), nameof(CanEditRoles), nameof(EditHint))]
    [NotifyCanExecuteChangedFor(nameof(AddRolesCommand), nameof(RemoveRolesCommand), nameof(OpenToEveryoneCommand))]
    private FormRoleRow? _selectedRow;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedRolesText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveRolesCommand))]
    private IList? _selectedRoleItems;

    public ObservableCollection<SummaryCard> SummaryCards { get; } = [];
    public ObservableCollection<RoleFilterOption> RoleOptions { get; } = [RoleFilterOption.All];
    public ObservableCollection<FormRoleAssignment> SelectedRoles { get; } = [];

    /// <summary>Lịch sử thêm/gỡ role của form đang chọn, trên môi trường đang kết nối (mới nhất trước).</summary>
    public ObservableCollection<ActionLogEntry> SelectedHistory { get; } = [];

    public string HistoryTitle => SelectedHistory.Count == 0
        ? "Lịch sử thay đổi (chưa có)"
        : $"Lịch sử thay đổi ({SelectedHistory.Count})";

    public IReadOnlyList<string> VisibilityOptions { get; } =
        [AllVisibilities, OnlySpecific, OnlyEveryone, OnlyUnreadable, OnlyNotScoped];

    public bool HasSelection => SelectedRow is not null;

    public string SelectedTitle => SelectedRow?.FormName ?? "";

    public string SelectedSubtitle => SelectedRow is { } row
        ? $"{row.EntityText} · {row.FormTypeText} · {row.StateText} · {row.ManagedText}"
        : "";

    public string SelectedHint => SelectedRow switch
    {
        null => "",
        { Visibility: FormVisibility.Everyone } =>
            "Form để “Everyone” – mọi user đọc được entity đều thấy form này.",
        { Visibility: FormVisibility.NotRoleScoped } =>
            "Quick View / Quick Create không gán được security role. D365 cho vào theo quyền Read entity.",
        { Visibility: FormVisibility.Unreadable } =>
            "⚠ Cấu hình role của form (displayconditions) hỏng XML nên không đọc được. " +
            "Mở Form settings trong D365 để xem danh sách thật.",
        { RoleCount: 0 } =>
            "Form đặt “Specific security roles” nhưng chưa chọn role nào – chỉ System Administrator thấy form này.",
        _ => "Double-click một role để mở role đó ở chế độ Roles.",
    };

    /// <summary>Gợi ý cần chú ý: form mở cho mọi role, không đọc được, hoặc chưa chọn role nào.</summary>
    public bool HintIsWarning => SelectedRow is
        { Visibility: FormVisibility.Everyone or FormVisibility.Unreadable }
        or { Visibility: FormVisibility.SpecificRoles, RoleCount: 0 };

    public bool HintIsInfo => HasSelection && !HintIsWarning;

    /// <summary>Chỉ sửa được form gán được role và đọc được cấu hình hiện tại.</summary>
    public bool CanEditRoles => SelectedRow is { Visibility: FormVisibility.SpecificRoles or FormVisibility.Everyone };

    public string EditHint => SelectedRow switch
    {
        { Visibility: FormVisibility.NotRoleScoped } => "Loại form này không gán được role.",
        { Visibility: FormVisibility.Unreadable } => "Không đọc được cấu hình – sửa trong Form settings của D365.",
        _ => "",
    };

    private List<FormRoleAssignment> PickedRoles => SelectedRoleItems?.OfType<FormRoleAssignment>().ToList() ?? [];

    public string SelectedRolesText => PickedRoles.Count == 0 ? "" : $"Đã chọn {PickedRoles.Count} role";

    partial void OnSearchTextChanged(string value) => RowsView?.Refresh();
    partial void OnVisibilityFilterChanged(string value) => RowsView?.Refresh();
    partial void OnOnlyActiveChanged(bool value) => RowsView?.Refresh();
    partial void OnRoleFilterChanged(RoleFilterOption value) => RowsView?.Refresh();

    partial void OnSelectedRowChanged(FormRoleRow? value)
    {
        SelectedRoles.Clear();
        foreach (var assignment in value?.Roles ?? [])
            SelectedRoles.Add(assignment);
        ShowHistory();
    }

    private void ReloadHistory()
    {
        var environment = Host.Service?.EnvironmentKey;
        _history = ActionLogStore.Load()
            .Where(e => e.RecordId is not null
                        && string.Equals(e.Environment, environment, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private void ShowHistory()
    {
        SelectedHistory.Clear();
        if (SelectedRow is { } row)
        {
            foreach (var entry in _history.Where(e => e.RecordId == row.FormId))
                SelectedHistory.Add(entry);
        }
        OnPropertyChanged(nameof(HistoryTitle));
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        await RunAsync("Đang đọc cấu hình role của form...", async () =>
        {
            var service = RequireService();
            var directory = await service.GetRoleDirectoryAsync(Progress);

            Progress.Report("Đang đọc form và dashboard...");
            var forms = await service.GetFormsAsync(Progress);
            var metadata = await service.GetEntityMetadataAsync();

            _directory = directory;
            _metadata = metadata;
            _rows = FormRoleAnalyzer.Build(forms, directory, metadata);
            ReloadHistory();

            RoleOptions.Clear();
            RoleOptions.Add(RoleFilterOption.All);
            foreach (var role in directory.Roots)
                RoleOptions.Add(new RoleFilterOption(role.Id, role.Name));
            RoleFilter = RoleFilterOption.All;

            RowsView = new ListCollectionView(_rows) { Filter = Matches };
            SelectedRow = null;
            BuildSummary(directory);
            ExportCommand.NotifyCanExecuteChanged();
        });
    }

    private void BuildSummary(RoleDirectory directory)
    {
        var scoped = _rows.Where(r => r.Visibility != FormVisibility.NotRoleScoped).ToList();

        SummaryCards.Clear();
        SummaryCards.Add(new SummaryCard("Form & dashboard", _rows.Count.ToString(),
            $"{scoped.Count} loại gán được role"));
        SummaryCards.Add(new SummaryCard("Gán role cụ thể",
            scoped.Count(r => r.Visibility == FormVisibility.SpecificRoles).ToString(), "Specific security roles"));
        SummaryCards.Add(new SummaryCard("Mở cho mọi role",
            scoped.Count(r => r.IsOpenToEveryone).ToString(), "Everyone"));
        SummaryCards.Add(new SummaryCard("Không đọc được",
            scoped.Count(r => r.Visibility == FormVisibility.Unreadable).ToString(), "displayconditions hỏng"));

        var orphans = _rows.Sum(r => r.Roles.Count(a => a.IsMissing));
        StatusText = $"{_rows.Count} form/dashboard · {directory.Roots.Count} role"
                     + (orphans > 0 ? $" · ⚠ {orphans} tham chiếu tới role không còn tồn tại" : "");
    }

    private bool Matches(object item)
    {
        if (item is not FormRoleRow row)
            return false;

        if (OnlyActive && !row.IsActive)
            return false;

        var visibilityOk = VisibilityFilter switch
        {
            OnlySpecific => row.Visibility == FormVisibility.SpecificRoles,
            OnlyEveryone => row.Visibility == FormVisibility.Everyone,
            OnlyUnreadable => row.Visibility == FormVisibility.Unreadable,
            OnlyNotScoped => row.Visibility == FormVisibility.NotRoleScoped,
            _ => true,
        };
        if (!visibilityOk)
            return false;

        if (!RoleFilter.IsAll && !row.HasRole(RoleFilter.RoleId))
            return false;

        return MainViewModel.Contains(row.FormName, SearchText)
               || MainViewModel.Contains(row.EntityDisplayName, SearchText)
               || MainViewModel.Contains(row.EntityLogicalName, SearchText);
    }

    [RelayCommand]
    private void OpenRole(object? item)
    {
        if (item is FormRoleAssignment { IsMissing: false } assignment)
            Host.OpenRole(assignment.RoleId);
    }

    private bool CanRemoveRoles => CanEditRoles && SelectedRow!.Visibility == FormVisibility.SpecificRoles && PickedRoles.Count > 0;

    private bool CanOpenToEveryone => SelectedRow is { Visibility: FormVisibility.SpecificRoles };

    [RelayCommand(CanExecute = nameof(CanEditRoles))]
    private async Task AddRolesAsync()
    {
        if (SelectedRow is not { } row)
            return;

        var assigned = row.Roles.Select(r => r.RoleId).ToHashSet();
        var available = _directory.Roots.Where(r => !assigned.Contains(r.Id)).ToList();
        var picked = PrincipalPickerWindow.Show(ActiveWindow, $"Thêm role cho form \"{row.FormName}\"",
            text => Task.FromResult(available.Where(r => MainViewModel.Contains(r.Name, text))
                .Select(r => new PrincipalSearchResult { Id = r.Id, Name = r.Name, Detail = r.ManagedText, BusinessUnitName = r.BusinessUnitName })
                .ToList()),
            actionText: "Thêm vào form", hint: "User có role được chọn sẽ thấy form này.", searchOnOpen: true);
        if (picked is null || picked.Count == 0)
            return;

        var names = string.Join("\n", picked.Select(p => "• " + p.Name));
        var warning = row.IsOpenToEveryone
            ? "\n\n⚠ Form đang mở cho mọi role (Everyone). Sau khi thêm, CHỈ các role này (và System Administrator) còn thấy form."
            : "";
        if (!Dialogs.Confirm($"Thêm {picked.Count} role cho form \"{row.FormName}\"?\n\n{names}{warning}{ManagedNote(row)}"))
            return;

        await SaveAsync(row, new DataverseService.FormRoleChange(picked.Select(p => p.Id).ToList(), []));
    }

    [RelayCommand(CanExecute = nameof(CanRemoveRoles))]
    private async Task RemoveRolesAsync()
    {
        if (SelectedRow is not { } row)
            return;

        var roles = PickedRoles;
        if (roles.Count >= row.RoleCount)
        {
            Dialogs.ShowWarning("Form phải còn ít nhất một role.\n\nMuốn mở form cho tất cả, dùng \"Mở cho mọi role\".");
            return;
        }
        if (!Dialogs.Confirm($"Gỡ {roles.Count} role khỏi form \"{row.FormName}\"?\n\n"
                             + string.Join("\n", roles.Select(r => "• " + r.DisplayName)) + ManagedNote(row)))
            return;

        await SaveAsync(row, new DataverseService.FormRoleChange([], roles.Select(r => r.RoleId).ToList()));
    }

    [RelayCommand(CanExecute = nameof(CanOpenToEveryone))]
    private async Task OpenToEveryoneAsync()
    {
        if (SelectedRow is not { } row)
            return;

        if (!Dialogs.Confirm($"Mở form \"{row.FormName}\" cho MỌI role (Everyone)?\n\n"
                             + $"Bỏ giới hạn {row.RoleCount} role hiện tại – mọi user đọc được entity đều thấy form này.{ManagedNote(row)}"))
            return;

        await SaveAsync(row, new DataverseService.FormRoleChange([], [], OpenToEveryone: true));
    }

    private static string ManagedNote(FormRoleRow row) => row.IsManaged
        ? "\n\nForm thuộc managed solution – thay đổi nằm ở lớp unmanaged và có thể bị ghi đè khi cập nhật solution."
        : "";

    private static Window? ActiveWindow =>
        Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive) ?? Application.Current?.MainWindow;

    /// <summary>
    /// Ghi lên Dataverse (kèm publish) rồi thay dòng trong bảng bằng cấu hình vừa ghi.
    /// Lịch sử được tải lại cả khi lỗi – thao tác lỗi giữa chừng cũng phải hiện ra để còn hoàn tác.
    /// </summary>
    private async Task SaveAsync(FormRoleRow row, DataverseService.FormRoleChange change)
    {
        await RunAsync("Đang lưu và publish form...", async () =>
        {
            var roleIds = await RequireService().ChangeFormRolesAsync(row.FormId, row.FormName, change);

            var info = new DataverseService.FormInfo(
                row.FormId, row.FormName, row.EntityLogicalName is "" ? "none" : row.EntityLogicalName, row.FormType,
                row.IsManaged, row.IsActive ? 1 : 0, [.. roleIds], roleIds.Count == 0);
            var updated = FormRoleAnalyzer.Build([info], _directory, _metadata).Single();

            var index = _rows.IndexOf(row);
            if (index >= 0)
                _rows[index] = updated;
            RowsView?.Refresh();
            SelectedRow = updated;
            BuildSummary(_directory);
            StatusText = $"Đã lưu và publish form \"{row.FormName}\" – {updated.VisibilityText}. Hoàn tác được trong Lịch sử thao tác.";
        });

        ReloadHistory();
        ShowHistory();
    }

    private bool CanExport => _rows.Count > 0;

    [RelayCommand(CanExecute = nameof(CanExport))]
    private void Export() =>
        Host.ExportWorkbook("FormTheoRole", workbook =>
        {
            ExcelExporter.AddSheet(workbook, "Form", _rows,
                new ExportColumn<FormRoleRow>("Entity", r => r.EntityText, 28),
                new ExportColumn<FormRoleRow>("Logical Name", r => r.EntityLogicalName, 28),
                new ExportColumn<FormRoleRow>("Form", r => r.FormName, 40),
                new ExportColumn<FormRoleRow>("Kiểu", r => r.FormTypeText),
                new ExportColumn<FormRoleRow>("Phân quyền", r => r.VisibilityText, 24),
                new ExportColumn<FormRoleRow>("Số role", r => r.RoleCount),
                new ExportColumn<FormRoleRow>("Role", r => r.RolesText, 70),
                new ExportColumn<FormRoleRow>("Trạng thái", r => r.StateText),
                new ExportColumn<FormRoleRow>("Managed", r => r.ManagedText),
                new ExportColumn<FormRoleRow>("Form Id", r => r.FormId.ToString(), 38));

            // Bảng phẳng: mỗi dòng một cặp form × role, tiện lọc và pivot trong Excel.
            var pairs = _rows
                .SelectMany(row => row.Roles.Select(role => new FormRolePair(row, role)))
                .ToList();

            ExcelExporter.AddSheet(workbook, "Form x Role", pairs,
                new ExportColumn<FormRolePair>("Entity", p => p.Form.EntityText, 28),
                new ExportColumn<FormRolePair>("Form", p => p.Form.FormName, 40),
                new ExportColumn<FormRolePair>("Kiểu", p => p.Form.FormTypeText),
                new ExportColumn<FormRolePair>("Role", p => p.Role.DisplayName, 40),
                new ExportColumn<FormRolePair>("Business Unit", p => p.Role.BusinessUnitText, 24),
                new ExportColumn<FormRolePair>("Role Id", p => p.Role.RoleId.ToString(), 38));
        });

    private sealed record FormRolePair(FormRoleRow Form, FormRoleAssignment Role);
}
