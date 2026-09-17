using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.ViewModels;

public sealed partial class CompareViewModel(DataverseService service, List<SecurityRoleInfo> roles, SecurityRoleInfo? initial)
    : ObservableObject
{
    public List<SecurityRoleInfo> Roles { get; } = roles;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CompareCommand))]
    private SecurityRoleInfo? _roleA = initial;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CompareCommand))]
    private SecurityRoleInfo? _roleB;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _summaryText = "Chọn 2 role rồi nhấn \"So sánh\".";
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private bool _onlyDifferences = true;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ExportCommand))]
    private ICollectionView? _rowsView;

    private List<PrivilegeDiffRow> _rows = [];

    partial void OnSearchTextChanged(string value) => RowsView?.Refresh();
    partial void OnOnlyDifferencesChanged(bool value) => RowsView?.Refresh();

    private bool CanCompare => RoleA is not null && RoleB is not null && RoleA.Id != RoleB.Id && !IsBusy;

    [RelayCommand(CanExecute = nameof(CanCompare))]
    private async Task CompareAsync()
    {
        if (RoleA is null || RoleB is null)
            return;

        IsBusy = true;
        SummaryText = "Đang so sánh...";
        try
        {
            var metadata = await service.GetEntityMetadataAsync();
            var catalog = await service.GetPrivilegeCatalogAsync();
            var privilegesA = await service.GetRolePrivilegesAsync(RoleA.Id);
            var privilegesB = await service.GetRolePrivilegesAsync(RoleB.Id);

            _rows = catalog
                .Select(p => new PrivilegeDiffRow
                {
                    Entity = p.EntityLogicalName ?? "",
                    EntityDisplayName = p.EntityLogicalName is { } name
                        ? metadata.GetValueOrDefault(name)?.DisplayName ?? name
                        : "(Quyền khác)",
                    Privilege = p.EntityLogicalName is not null && p.AccessRight != AccessRight.None
                        ? $"{p.AccessRight} ({p.Name})"
                        : p.Name,
                    DepthA = privilegesA.GetValueOrDefault(p.Id),
                    DepthB = privilegesB.GetValueOrDefault(p.Id),
                })
                .Where(r => r.DepthA > PrivilegeDepth.None || r.DepthB > PrivilegeDepth.None)
                .DistinctBy(r => (r.Entity, r.Privilege))
                .OrderBy(r => r.EntityDisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(r => r.Privilege)
                .ToList();

            RowsView = new ListCollectionView(_rows) { Filter = Filter };

            var onlyA = _rows.Count(r => r.DepthB == PrivilegeDepth.None);
            var onlyB = _rows.Count(r => r.DepthA == PrivilegeDepth.None);
            var diffDepth = _rows.Count(r => r.IsDifferent) - onlyA - onlyB;
            SummaryText = $"{_rows.Count} privilege được cấp ở ít nhất 1 role  ·  Chỉ A: {onlyA}  ·  Chỉ B: {onlyB}  ·  Khác mức: {diffDepth}  ·  Giống nhau: {_rows.Count(r => !r.IsDifferent)}";
        }
        catch (Exception ex)
        {
            SummaryText = "Lỗi: " + ex.Message;
            Dialogs.ShowError(ex);
        }
        finally
        {
            IsBusy = false;
            CompareCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand]
    private void Swap() => (RoleA, RoleB) = (RoleB, RoleA);

    private bool CanExport => RowsView is not null;

    [RelayCommand(CanExecute = nameof(CanExport))]
    private void Export()
    {
        if (RoleA is null || RoleB is null || RowsView is null)
            return;

        var path = Dialogs.SaveExcel($"SoSanhRole_{DateTime.Now:yyyyMMdd_HHmm}.xlsx");
        if (path is null)
            return;

        try
        {
            ExcelExporter.ExportComparison(RoleA.Name, RoleB.Name, RowsView.Cast<PrivilegeDiffRow>(), path);
            if (Dialogs.Confirm("Xuất Excel thành công. Mở file ngay?"))
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Dialogs.ShowError(ex);
        }
    }

    private bool Filter(object item) =>
        item is PrivilegeDiffRow row
        && (!OnlyDifferences || row.IsDifferent)
        && (string.IsNullOrWhiteSpace(SearchText)
            || row.Entity.Contains(SearchText.Trim(), StringComparison.CurrentCultureIgnoreCase)
            || row.EntityDisplayName.Contains(SearchText.Trim(), StringComparison.CurrentCultureIgnoreCase)
            || row.Privilege.Contains(SearchText.Trim(), StringComparison.CurrentCultureIgnoreCase));
}
