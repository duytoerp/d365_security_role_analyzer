using System.Collections;
using System.Windows;
using System.Windows.Controls;

namespace SecurityRoleAnalyzer.Controls;

/// <summary>
/// Đưa danh sách dòng đang chọn của DataGrid lên ViewModel (DataGrid.SelectedItems không bind được).
/// Dùng: c:GridSelection.SelectedItems="{Binding SelectedX, Mode=OneWayToSource}".
/// </summary>
public static class GridSelection
{
    public static readonly DependencyProperty SelectedItemsProperty = DependencyProperty.RegisterAttached(
        "SelectedItems", typeof(IList), typeof(GridSelection), new PropertyMetadata(null));

    // Cờ nội bộ để chỉ đăng ký SelectionChanged một lần cho mỗi DataGrid.
    private static readonly DependencyProperty IsHookedProperty = DependencyProperty.RegisterAttached(
        "IsHooked", typeof(bool), typeof(GridSelection), new PropertyMetadata(false));

    /// <summary>Bật đồng bộ selection. Đặt c:GridSelection.Enabled="True" trên DataGrid.</summary>
    public static readonly DependencyProperty EnabledProperty = DependencyProperty.RegisterAttached(
        "Enabled", typeof(bool), typeof(GridSelection), new PropertyMetadata(false, OnEnabledChanged));

    public static IList? GetSelectedItems(DependencyObject obj) => (IList?)obj.GetValue(SelectedItemsProperty);
    public static void SetSelectedItems(DependencyObject obj, IList? value) => obj.SetValue(SelectedItemsProperty, value);
    public static bool GetEnabled(DependencyObject obj) => (bool)obj.GetValue(EnabledProperty);
    public static void SetEnabled(DependencyObject obj, bool value) => obj.SetValue(EnabledProperty, value);

    private static void OnEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not DataGrid grid || e.NewValue is not true || (bool)grid.GetValue(IsHookedProperty))
            return;

        grid.SetValue(IsHookedProperty, true);
        grid.SelectionChanged += (_, args) =>
        {
            if (ReferenceEquals(args.OriginalSource, grid))
                grid.SetCurrentValue(SelectedItemsProperty, grid.SelectedItems.Cast<object>().ToList());
        };
    }
}
