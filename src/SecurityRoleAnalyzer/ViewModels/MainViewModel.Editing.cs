using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecurityRoleAnalyzer.Controls;
using SecurityRoleAnalyzer.Models;
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
}
