using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SecurityRoleAnalyzer.Controls;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.ViewModels;

/// <summary>Chỉnh sửa privilege của role trực tiếp trên ma trận quyền, sao chép role.</summary>
public sealed partial class MainViewModel : IPrivilegeEditHost
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PendingChangesText), nameof(EditButtonText))]
    [NotifyCanExecuteChangedFor(nameof(SavePrivilegesCommand), nameof(DiscardPrivilegesCommand))]
    private bool _isEditingPrivileges;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PendingChangesText))]
    [NotifyCanExecuteChangedFor(nameof(SavePrivilegesCommand), nameof(DiscardPrivilegesCommand))]
    private int _pendingChangeCount;

    public string EditButtonText => IsEditingPrivileges ? "✖ Thoát chế độ sửa" : "✏ Sửa quyền";

    public string PendingChangesText => !IsEditingPrivileges
        ? ""
        : PendingChangeCount == 0
            ? "Đang sửa: click trái vào ô để tăng mức, click phải để giảm mức."
            : $"{PendingChangeCount} thay đổi chưa lưu (ô nền vàng).";

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private void ToggleEditPrivileges()
    {
        if (Analysis is null)
            return;

        if (IsEditingPrivileges)
        {
            if (PendingChangeCount > 0 && !Dialogs.Confirm($"Bỏ {PendingChangeCount} thay đổi chưa lưu?"))
                return;
            RevertPendingChanges();
            IsEditingPrivileges = false;
            return;
        }

        if (Analysis.Role.IsManaged
            && !Dialogs.Confirm("Role này thuộc managed solution – thay đổi có thể bị ghi đè khi cập nhật solution, và một số role hệ thống không cho phép sửa.\n\nVẫn tiếp tục?"))
            return;

        IsEditingPrivileges = true;
    }

    public void CycleDepth(object row, string cellPath, bool backward)
    {
        if (!IsEditingPrivileges)
            return;

        switch (row)
        {
            case EntityPrivilegeRow entity when Enum.TryParse<AccessRight>(cellPath, out var right):
                var cell = entity.Get(right);
                if (!cell.Exists || cell.Definition is null)
                    return;
                entity.Replace(right, cell.WithDepth(cell.Definition.Cycle(cell.Depth, backward)));
                break;
            case MiscPrivilegeRow misc when misc.Definition is not null:
                misc.Depth = misc.Definition.Cycle(misc.Depth, backward);
                break;
            default:
                return;
        }
        PendingChangeCount = CollectPendingChanges().Count;
    }

    private List<(PrivilegeDefinition Privilege, PrivilegeDepth Depth, string Label)> CollectPendingChanges()
    {
        var result = new List<(PrivilegeDefinition, PrivilegeDepth, string)>();
        if (Analysis is null)
            return result;

        foreach (var row in Analysis.EntityRows)
        foreach (var right in EntityPrivilegeRow.StandardRights)
        {
            var cell = row.Get(right);
            if (cell.IsChanged && cell.Definition is not null)
                result.Add((cell.Definition, cell.Depth, $"{row.DisplayName} – {right}: {cell.OriginalDepth.ToText()} → {cell.Depth.ToText()}"));
        }
        foreach (var misc in Analysis.MiscPrivileges.Where(m => m.IsChanged && m.Definition is not null))
            result.Add((misc.Definition!, misc.Depth, $"{misc.Name}: {misc.OriginalDepth.ToText()} → {misc.Depth.ToText()}"));
        return result;
    }

    private void RevertPendingChanges()
    {
        if (Analysis is null)
            return;
        foreach (var row in Analysis.EntityRows)
        foreach (var right in EntityPrivilegeRow.StandardRights)
        {
            var cell = row.Get(right);
            if (cell.IsChanged)
                row.Replace(right, cell.WithDepth(cell.OriginalDepth));
        }
        foreach (var misc in Analysis.MiscPrivileges.Where(m => m.IsChanged))
            misc.Depth = misc.OriginalDepth;
        PendingChangeCount = 0;
    }

    private bool CanSavePrivileges => IsEditingPrivileges && PendingChangeCount > 0;

    [RelayCommand(CanExecute = nameof(CanSavePrivileges))]
    private async Task SavePrivilegesAsync()
    {
        if (_service is not { } service || Analysis is not { } analysis)
            return;

        var changes = CollectPendingChanges();
        var preview = string.Join("\n", changes.Take(20).Select(c => "• " + c.Label));
        if (changes.Count > 20)
            preview += $"\n... và {changes.Count - 20} thay đổi khác";
        if (!Dialogs.Confirm($"Lưu {changes.Count} thay đổi privilege cho role \"{analysis.Role.Name}\"?\n\n{preview}\n\nPrivilege hiện tại sẽ được sao lưu trước khi lưu (hoàn tác được trong Lịch sử thao tác)."))
            return;

        var saved = false;
        await RunBusyAsync("Đang lưu privilege...", async () =>
        {
            var backup = await service.UpdateRolePrivilegesAsync(analysis.Role.Id, analysis.Role.Name,
                changes.Select(c => (c.Privilege, c.Depth)).ToList());
            StatusText = $"Đã lưu {changes.Count} thay đổi. Bản sao lưu: {backup}";
            saved = true;
        });

        if (saved)
        {
            IsEditingPrivileges = false;
            PendingChangeCount = 0;
            await LoadRoleAsync(analysis.Role);
        }
    }

    private bool CanDiscardPrivileges => IsEditingPrivileges && PendingChangeCount > 0;

    [RelayCommand(CanExecute = nameof(CanDiscardPrivileges))]
    private void DiscardPrivileges() => RevertPendingChanges();

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task CopyRoleAsync()
    {
        if (_service is not { } service || Analysis is not { } analysis)
            return;

        var name = InputDialog.Show(App.Current.MainWindow, "Sao chép role",
            $"Tên role mới (sao chép toàn bộ privilege từ \"{analysis.Role.Name}\"):", $"{analysis.Role.Name} - Copy");
        if (string.IsNullOrWhiteSpace(name))
            return;
        if (Roles.Any(r => r.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase))
            && !Dialogs.Confirm($"Đã có role tên \"{name}\". Vẫn tạo?"))
            return;

        Guid newId = Guid.Empty;
        await RunBusyAsync("Đang sao chép role...", async () =>
        {
            newId = await service.CopyRoleAsync(analysis.Role, name.Trim());
            await LoadRolesAsync();
            StatusText = $"Đã tạo role \"{name}\".";
        });
        if (newId != Guid.Empty)
            OpenRole(newId);
    }

    #region Tạo / sửa / xóa role

    [RelayCommand(CanExecute = nameof(IsConnected))]
    private async Task NewRoleAsync()
    {
        if (_service is not { } service)
            return;

        var name = InputDialog.Show(App.Current.MainWindow, "Tạo security role",
            "Tên role mới (chưa có privilege nào):", "");
        if (string.IsNullOrWhiteSpace(name))
            return;
        if (Roles.Any(r => r.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase))
            && !Dialogs.Confirm($"Đã có role tên \"{name}\". Vẫn tạo?"))
            return;

        // Role được tạo trong BU gốc; Dataverse tự sinh bản sao cho các BU con.
        var rootBu = await GetRootBusinessUnitAsync(service);
        if (rootBu is not { } bu)
            return;

        var newId = Guid.Empty;
        await RunBusyAsync("Đang tạo role...", async () =>
        {
            newId = await service.CreateRoleAsync(name.Trim(), bu.Id, bu.Name);
            await LoadRolesAsync();
            StatusText = $"Đã tạo role \"{name}\" trong Business Unit \"{bu.Name}\".";
        });
        if (newId != Guid.Empty)
            OpenRole(newId);
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task RenameRoleAsync()
    {
        if (_service is not { } service || Analysis is not { } analysis)
            return;

        var role = analysis.Role;
        if (role.IsManaged
            && !Dialogs.Confirm("Role này thuộc managed solution – đổi tên có thể bị ghi đè khi cập nhật solution.\n\nVẫn tiếp tục?"))
            return;

        var name = InputDialog.Show(App.Current.MainWindow, "Đổi tên role", "Tên mới:", role.Name);
        if (string.IsNullOrWhiteSpace(name) || name.Trim() == role.Name)
            return;

        await RunBusyAsync("Đang đổi tên role...", async () =>
        {
            await service.UpdateRoleAsync(role, name.Trim(), role.IsInherited);
            await LoadRolesAsync();
            StatusText = $"Đã đổi tên thành \"{name.Trim()}\".";
        });
        if (Roles.FirstOrDefault(r => r.Id == role.Id) is { } updated)
            SelectedRole = updated;
    }

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task DeleteRoleAsync()
    {
        if (_service is not { } service || Analysis is not { } analysis)
            return;

        var role = analysis.Role;
        var users = analysis.Users.Count;
        var teams = analysis.Teams.Count;
        var warning = users + teams > 0
            ? $"\n\n⚠ Role đang được gán cho {users} user và {teams} team – họ sẽ mất quyền này ngay lập tức."
            : "";

        if (!Dialogs.Confirm($"Xóa vĩnh viễn role \"{role.Name}\"?{warning}\n\nThao tác này KHÔNG hoàn tác được."))
            return;
        if (!Dialogs.Confirm($"Xác nhận lần cuối: xóa role \"{role.Name}\"?"))
            return;

        await RunBusyAsync("Đang xóa role...", async () =>
        {
            await service.DeleteRoleAsync(role.Id, role.Name);
            SelectedRole = null;
            ClearAnalysis();
            await LoadRolesAsync();
            StatusText = $"Đã xóa role \"{role.Name}\".";
        });
    }

    /// <summary>Business Unit gốc (không có BU cha) – nơi tạo role mới.</summary>
    private async Task<BusinessUnitInfo?> GetRootBusinessUnitAsync(DataverseService service)
    {
        var units = await service.GetBusinessUnitsAsync();
        var root = units.FirstOrDefault(u => u.ParentId is null);
        if (root is null)
            Dialogs.ShowWarning("Không xác định được Business Unit gốc để tạo role.");
        return root;
    }

    #endregion

    #region Xuất / nhập định nghĩa role giữa các môi trường

    [RelayCommand(CanExecute = nameof(HasAnalysis))]
    private async Task ExportRoleDefinitionAsync()
    {
        if (_service is not { } service || Analysis is not { } analysis)
            return;

        var dialog = new SaveFileDialog
        {
            Title = "Xuất định nghĩa role",
            FileName = $"{SafeFileName(analysis.Role.Name)}_{DateTime.Now:yyyyMMdd}.role.json",
            Filter = "Định nghĩa role (*.role.json)|*.role.json|JSON (*.json)|*.json",
            DefaultExt = ".role.json",
        };
        if (dialog.ShowDialog() != true)
            return;

        await RunBusyAsync("Đang xuất định nghĩa role...", async () =>
        {
            var definition = await RoleDefinitionService.ExportAsync(service, analysis.Role);
            RoleDefinitionService.Save(definition, dialog.FileName);
            StatusText = $"Đã xuất \"{definition.Name}\": {definition.GrantedCount} privilege, {definition.Apps.Count} app → {dialog.FileName}";
        });
    }

    [RelayCommand(CanExecute = nameof(IsConnected))]
    private async Task ImportRoleDefinitionAsync()
    {
        if (_service is not { } service)
            return;

        var dialog = new OpenFileDialog
        {
            Title = "Chọn file định nghĩa role",
            Filter = "Định nghĩa role (*.role.json;*.json)|*.role.json;*.json",
        };
        if (dialog.ShowDialog() != true)
            return;

        RoleDefinition definition;
        try
        {
            definition = RoleDefinitionService.Load(dialog.FileName);
        }
        catch (Exception ex)
        {
            Dialogs.ShowError(ex, "Đọc file định nghĩa role");
            return;
        }

        var existing = Roles.FirstOrDefault(r => r.Name.Equals(definition.Name, StringComparison.OrdinalIgnoreCase));
        var target = RoleImportWindow.Show(App.Current.MainWindow, definition, existing);
        if (target is null)
            return;

        var rootBu = target.Value.TargetRoleId is null ? await GetRootBusinessUnitAsync(service) : null;
        if (target.Value.TargetRoleId is null && rootBu is null)
            return;

        var newRoleId = Guid.Empty;
        await RunBusyAsync($"Đang áp định nghĩa role \"{definition.Name}\"...", async () =>
        {
            var result = await RoleDefinitionService.ApplyAsync(service, definition, target.Value.TargetRoleId,
                rootBu?.Id ?? Guid.Empty, rootBu?.Name ?? "", target.Value.LinkApps);
            newRoleId = result.RoleId;
            await LoadRolesAsync();
            StatusText = result.Summary;

            if (result.MissingPrivileges.Count > 0 || result.MissingApps.Count > 0)
            {
                var detail = result.MissingPrivileges.Count > 0
                    ? $"{result.MissingPrivileges.Count} privilege không có trên môi trường này:\n"
                      + string.Join("\n", result.MissingPrivileges.Take(30))
                    : "";
                if (result.MissingApps.Count > 0)
                    detail += $"\n\n{result.MissingApps.Count} app không tìm thấy:\n" + string.Join("\n", result.MissingApps.Take(15));
                Dialogs.ShowWarning(detail.Trim());
            }
        });

        if (newRoleId != Guid.Empty)
            OpenRole(newRoleId);
    }

    #endregion
}
