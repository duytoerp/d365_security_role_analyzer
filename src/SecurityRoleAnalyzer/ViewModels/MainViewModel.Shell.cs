using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using ClosedXML.Excel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.ViewModels;

public enum AppMode
{
    Roles,
    Teams,
    Users,
    Apps,
    FieldSecurity,
    BusinessUnits,
}

/// <summary>Khung ứng dụng: chế độ, điều hướng, kết nối nhanh, công cụ và xuất Excel dùng chung.</summary>
public sealed partial class MainViewModel
{
    public UserManagerViewModel UserManager { get; }
    public AppManagerViewModel AppManager { get; }
    public FieldSecurityViewModel FieldSecurity { get; }
    public BusinessUnitsViewModel BusinessUnits { get; }

    #region Modes & navigation

    [ObservableProperty] private AppMode _mode;
    private bool _suppressModeLoad;

    partial void OnModeChanged(AppMode value)
    {
        if (!_suppressModeLoad)
            _ = EnsureModeLoadedAsync(value);
    }

    private void SetModeSilently(AppMode mode)
    {
        _suppressModeLoad = true;
        Mode = mode;
        _suppressModeLoad = false;
    }

    /// <summary>Tải danh sách của chế độ lần đầu mở (lazy).</summary>
    internal async Task EnsureModeLoadedAsync(AppMode mode)
    {
        if (_service is null)
            return;

        (bool Loaded, Func<Task> Load, string Text) plan = mode switch
        {
            AppMode.Teams => (TeamManager.IsLoaded, TeamManager.LoadTeamsAsync, "Đang tải danh sách team..."),
            AppMode.Users => (UserManager.IsLoaded, UserManager.LoadListAsync, "Đang tải danh sách user..."),
            AppMode.Apps => (AppManager.IsLoaded, AppManager.LoadListAsync, "Đang tải Model-driven App..."),
            AppMode.FieldSecurity => (FieldSecurity.IsLoaded, FieldSecurity.LoadListAsync, "Đang tải Field Security Profile..."),
            AppMode.BusinessUnits => (BusinessUnits.IsLoaded, BusinessUnits.LoadListAsync, "Đang tải Business Unit và phân quyền..."),
            _ => (true, () => Task.CompletedTask, ""),
        };

        if (!plan.Loaded)
            await RunBusyAsync(plan.Text, plan.Load);
    }

    private async Task NavigateAsync(AppMode mode, Func<Task> afterLoad)
    {
        SetModeSilently(mode);
        await EnsureModeLoadedAsync(mode);
        await afterLoad();
    }

    internal void OpenTeam(Guid teamId) =>
        _ = NavigateAsync(AppMode.Teams, () =>
        {
            TeamManager.SelectTeam(teamId);
            return Task.CompletedTask;
        });

    internal Task OpenUserAsync(Guid userId) => NavigateAsync(AppMode.Users, () => UserManager.SelectUserAsync(userId));

    internal void OpenRecord(string entity, Guid id)
    {
        if (_service is null)
            return;
        var url = $"{_service.OrganizationUrl}/main.aspx?pagetype=entityrecord&etn={entity}&id={id}";
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    #endregion

    #region Connection profiles

    public ObservableCollection<ConnectionProfile> Profiles { get; } = [];

    [ObservableProperty] private ConnectionProfile? _selectedProfile;
    private bool _suppressProfileConnect;

    partial void OnSelectedProfileChanged(ConnectionProfile? value)
    {
        if (value is not null && !_suppressProfileConnect)
            _ = QuickConnectAsync(value);
    }

    private void ReloadProfiles(ConnectionProfile? current)
    {
        _suppressProfileConnect = true;
        Profiles.Clear();
        foreach (var profile in ConnectionProfileStore.Load())
            Profiles.Add(profile);
        SelectedProfile = current is null
            ? null
            : Profiles.FirstOrDefault(p => p.AuthType == current.AuthType && string.Equals(p.Url, current.Url, StringComparison.OrdinalIgnoreCase));
        _suppressProfileConnect = false;
    }

    private ConnectionProfile? _currentProfile;

    private async Task QuickConnectAsync(ConnectionProfile profile)
    {
        string? connectionString = null;
        if (profile.CanQuickConnect)
        {
            try
            {
                connectionString = profile.BuildConnectionString(profile.GetSecret(), null);
            }
            catch (ArgumentException)
            {
                connectionString = null;
            }
        }

        if (connectionString is null)
        {
            var result = ConnectionWindow.Show(App.Current.MainWindow, profile);
            if (result is null)
            {
                ReloadProfiles(_currentProfile);
                return;
            }
            connectionString = result.Value.ConnectionString;
            profile = result.Value.Profile;
        }

        await ConnectWithAsync(connectionString, profile);
    }

    internal async Task ConnectWithAsync(string connectionString, ConnectionProfile profile)
    {
        var connected = false;
        await RunBusyAsync($"Đang kết nối tới {profile.DisplayName}...", async () =>
        {
            var service = await DataverseService.ConnectAsync(connectionString);
            _service?.Dispose();
            _service = service;
            ConnectionProfileStore.Save(profile);
            _currentProfile = profile;

            IsConnected = true;
            ConnectionText = $"{service.OrganizationName} · {service.OrganizationUrl}" +
                             (string.IsNullOrEmpty(service.CurrentUserName) ? "" : $" · {service.CurrentUserName}");
            ClearAnalysis();
            SelectedRole = null;
            TeamManager.Clear();
            UserManager.Clear();
            AppManager.Clear();
            FieldSecurity.Clear();
            BusinessUnits.Clear();
            await LoadRolesAsync();
            connected = true;
        });

        ReloadProfiles(_currentProfile);
        if (connected)
            await EnsureModeLoadedAsync(Mode);
    }

    #endregion

    #region Tools

    private bool CanUseTools => IsConnected;

    private static void ShowTool(Window window, Func<Task>? onLoaded = null)
    {
        window.Owner = App.Current.MainWindow;
        if (onLoaded is not null)
            window.Loaded += async (_, _) => await onLoaded();
        window.Show();
    }

    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private void OpenLookup()
    {
        var vm = new LookupViewModel(this);
        ShowTool(new LookupWindow { DataContext = vm }, vm.LoadAsync);
    }

    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private void OpenAccessReview()
    {
        var vm = new AccessReviewViewModel(this);
        ShowTool(new AccessReviewWindow { DataContext = vm }, vm.LoadAsync);
    }

    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private void OpenBulkPrivileges()
    {
        var vm = new BulkPrivilegeViewModel(this);
        ShowTool(new BulkPrivilegeWindow { DataContext = vm }, vm.LoadAsync);
    }

    [RelayCommand]
    private void OpenSnapshot() => ShowTool(new SnapshotWindow { DataContext = new SnapshotViewModel(this) });

    [RelayCommand(CanExecute = nameof(IsConnected))]
    private void OpenRecordAccess()
    {
        var vm = new RecordAccessViewModel(this);
        ShowTool(new RecordAccessWindow { DataContext = vm }, vm.LoadContextAsync);
    }

    /// <summary>
    /// Chiều ngược của tab Components. Tham số tùy chọn: tên entity hoặc dòng component
    /// để mở sẵn với bộ lọc tương ứng.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private void OpenFormRoles(object? parameter)
    {
        var vm = new FormRoleViewModel(this);

        var entity = parameter switch
        {
            RoleComponent component => component.EntityLogicalName,
            string text => text,
            _ => "",
        };
        if (!string.IsNullOrWhiteSpace(entity))
            vm.SearchText = entity;

        ShowTool(new FormRoleWindow { DataContext = vm }, vm.LoadAsync);
    }

    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private void OpenRoleOverlap()
    {
        var vm = new RoleOverlapViewModel(this);
        ShowTool(new RoleOverlapWindow { DataContext = vm }, vm.LoadAsync);
    }

    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private void OpenAudit()
    {
        var vm = new AuditViewModel(this);
        ShowTool(new AuditWindow { DataContext = vm }, vm.LoadAsync);
    }

    [RelayCommand]
    private void EditPolicy()
    {
        var path = SecurityPolicy.SaveTemplate();
        StatusText = $"Bộ quy tắc rà soát: {path}";
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    [RelayCommand]
    private async Task ReloadPolicyAsync()
    {
        SecurityPolicy.Reload();
        StatusText = SecurityPolicy.IsCustom
            ? "Đã nạp lại bộ quy tắc từ policy.json."
            : "Đang dùng bộ quy tắc mặc định (chưa có policy.json).";

        // Phân tích lại mục đang xem để áp quy tắc mới.
        if (Mode == AppMode.Roles && SelectedRole is { } role)
            await LoadRoleAsync(role);
    }

    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private void OpenImport() => ShowTool(new ImportWindow { DataContext = new ImportViewModel(this) });

    [RelayCommand]
    private void OpenHistory()
    {
        var vm = new HistoryViewModel(this);
        vm.Load();
        ShowTool(new HistoryWindow { DataContext = vm });
    }

    [RelayCommand(CanExecute = nameof(CanUseTools))]
    private async Task RestoreBackupAsync()
    {
        if (_service is not { } service)
            return;

        var folder = PrivilegeBackupStore.Folder(service.EnvironmentKey);
        var dialog = new OpenFileDialog
        {
            Title = "Chọn bản sao lưu privilege",
            Filter = "Bản sao lưu (*.json)|*.json",
            InitialDirectory = Directory.Exists(folder) ? folder : ConnectionProfileStore.AppDataFolder,
        };
        if (dialog.ShowDialog() != true)
            return;

        PrivilegeBackup backup;
        try
        {
            backup = PrivilegeBackupStore.Load(dialog.FileName);
        }
        catch (Exception ex)
        {
            Dialogs.ShowError(ex);
            return;
        }

        var sameEnvironment = string.Equals(backup.Environment, service.EnvironmentKey, StringComparison.OrdinalIgnoreCase);
        var picked = PrincipalPickerWindow.Show(App.Current.MainWindow,
            "Chọn role để khôi phục privilege",
            text => Task.FromResult(Roles
                .Where(r => Contains(r.Name, string.IsNullOrWhiteSpace(text) && sameEnvironment ? backup.RoleName : text))
                .Select(r => new PrincipalSearchResult { Id = r.Id, Name = r.Name, Detail = r.ManagedText, BusinessUnitName = r.BusinessUnitName })
                .ToList()),
            actionText: "Khôi phục vào role",
            hint: $"Bản sao lưu \"{backup.RoleName}\" ({backup.Environment}, {backup.CreatedOn:dd/MM/yyyy HH:mm}) – {backup.Privileges.Count} privilege. Toàn bộ privilege của role đích sẽ bị thay thế.",
            searchOnOpen: true);
        if (picked is not { Count: 1 })
        {
            if (picked is { Count: > 1 })
                Dialogs.ShowWarning("Vui lòng chọn đúng 1 role đích.");
            return;
        }

        var target = picked[0];
        await RunBusyAsync($"Đang khôi phục privilege cho \"{target.Name}\"...", async () =>
        {
            var missing = await service.RestorePrivilegeBackupAsync(backup, target.Id, target.Name);
            StatusText = $"Đã khôi phục {backup.Privileges.Count - missing.Count} privilege cho \"{target.Name}\".";
            if (missing.Count > 0)
                Dialogs.ShowWarning($"{missing.Count} privilege không tồn tại trên môi trường này:\n\n" + string.Join("\n", missing.Take(40)));
        });
        if (SelectedRole?.Id == target.Id)
            await LoadRoleAsync(SelectedRole);
    }

    [RelayCommand]
    private static void OpenDataFolder()
    {
        Directory.CreateDirectory(ConnectionProfileStore.AppDataFolder);
        Process.Start(new ProcessStartInfo(ConnectionProfileStore.AppDataFolder) { UseShellExecute = true });
    }

    [RelayCommand]
    private void OpenErrorLog()
    {
        if (!File.Exists(ErrorLog.FilePath))
        {
            StatusText = "Chưa có lỗi nào được ghi lại.";
            return;
        }
        Process.Start(new ProcessStartInfo(ErrorLog.FilePath) { UseShellExecute = true });
    }

    #endregion

    #region Giao diện & phím tắt

    public bool IsThemeSystem => Theme.Selected == AppTheme.System;
    public bool IsThemeLight => Theme.Selected == AppTheme.Light;
    public bool IsThemeDark => Theme.Selected == AppTheme.Dark;

    [RelayCommand]
    private void SetTheme(string? name)
    {
        if (!Enum.TryParse<AppTheme>(name, out var theme))
            return;

        Theme.Apply(theme);
        var settings = AppSettings.Current;
        settings.Theme = theme;
        settings.Save();

        OnPropertyChanged(nameof(IsThemeSystem));
        OnPropertyChanged(nameof(IsThemeLight));
        OnPropertyChanged(nameof(IsThemeDark));
        StatusText = $"Giao diện: {Theme.ToText(theme)}";
    }

    [RelayCommand]
    private void SetMode(string? name)
    {
        if (Enum.TryParse<AppMode>(name, out var mode))
            Mode = mode;
    }

    /// <summary>Ctrl+F: đưa con trỏ về ô tìm kiếm của chế độ đang mở.</summary>
    public event Action? SearchFocusRequested;

    [RelayCommand]
    private void FocusSearch() => SearchFocusRequested?.Invoke();

    /// <summary>Ctrl+Shift+C: chép dòng đang chọn (kèm Id) ra clipboard.</summary>
    [RelayCommand]
    private void CopySelection()
    {
        var text = Mode switch
        {
            AppMode.Roles => SelectedRole is { } role ? $"{role.Name}\t{role.Id}\t{role.BusinessUnitName}" : null,
            AppMode.Teams => TeamManager.SelectedTeam is { } team ? $"{team.Name}\t{team.Id}\t{team.BusinessUnitName}" : null,
            AppMode.Users => UserManager.SelectedUser is { } user ? $"{user.FullName}\t{user.Id}\t{user.DomainName}" : null,
            AppMode.Apps => AppManager.SelectedApp is { } app ? $"{app.Name}\t{app.Id}\t{app.UniqueName}" : null,
            AppMode.FieldSecurity => FieldSecurity.SelectedProfile is { } profile ? $"{profile.Name}\t{profile.Id}" : null,
            AppMode.BusinessUnits => BusinessUnits.SelectedNode is { } node ? $"{node.Unit.Name}\t{node.Unit.Id}" : null,
            _ => null,
        };

        if (text is null)
        {
            StatusText = "Chưa chọn mục nào để sao chép.";
            return;
        }

        StatusText = Dialogs.CopyToClipboard(text)
            ? "Đã sao chép: " + text.Split('\t')[0]
            : "Không sao chép được vào clipboard.";
    }

    [RelayCommand]
    private static void ShowShortcuts() => ShortcutsWindow.Show(App.Current.MainWindow);

    /// <summary>Hỏi nơi lưu, dựng workbook và mở file sau khi xuất.</summary>
    internal void ExportWorkbook(string baseName, Action<XLWorkbook> build)
    {
        var path = Dialogs.SaveExcel($"{SafeFileName(baseName)}_{DateTime.Now:yyyyMMdd_HHmm}.xlsx");
        if (path is null)
            return;

        try
        {
            using (var workbook = new XLWorkbook())
            {
                build(workbook);
                workbook.SaveAs(path);
            }
            StatusText = "Đã xuất: " + path;
            if (Dialogs.Confirm("Xuất Excel thành công. Mở file ngay?"))
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Dialogs.ShowError(ex);
        }
    }

    #endregion
}
