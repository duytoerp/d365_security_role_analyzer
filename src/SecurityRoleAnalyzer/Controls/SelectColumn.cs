using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace SecurityRoleAnalyzer.Controls;

/// <summary>
/// Cột checkbox để chọn nhiều dòng trên DataGrid (SelectionMode="Extended").
/// Header có ô "chọn tất cả"; click vào ô chỉ đảo trạng thái chọn của dòng đó, giữ nguyên các dòng khác.
/// </summary>
public sealed class SelectColumn : DataGridTemplateColumn
{
    private readonly CheckBox _header;
    private DataGrid? _grid;
    private bool _syncing;

    public SelectColumn()
    {
        Width = new DataGridLength(42);
        CanUserResize = false;
        CanUserReorder = false;
        CanUserSort = false;

        _header = new CheckBox { Margin = new Thickness(0), Focusable = false, ToolTip = "Chọn / bỏ chọn tất cả" };
        _header.Checked += OnHeaderChanged;
        _header.Unchecked += OnHeaderChanged;
        _header.Loaded += OnHeaderLoaded;
        Header = _header;

        // Cả ô nhận click; CheckBox bên trong chỉ để hiển thị trạng thái IsSelected của dòng.
        var cell = new FrameworkElementFactory(typeof(Border));
        cell.SetValue(Border.BackgroundProperty, Brushes.Transparent);
        cell.SetValue(FrameworkElement.CursorProperty, Cursors.Hand);
        cell.AddHandler(UIElement.PreviewMouseLeftButtonDownEvent, new MouseButtonEventHandler(OnCellMouseDown));

        var check = new FrameworkElementFactory(typeof(CheckBox));
        check.SetValue(FrameworkElement.MarginProperty, new Thickness(0));
        check.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        check.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        check.SetValue(UIElement.FocusableProperty, false);
        check.SetValue(UIElement.IsHitTestVisibleProperty, false);
        check.SetBinding(ToggleButton.IsCheckedProperty, new Binding(nameof(DataGridRow.IsSelected))
        {
            RelativeSource = new RelativeSource(RelativeSourceMode.FindAncestor, typeof(DataGridRow), 1),
            Mode = BindingMode.OneWay,
        });
        cell.AppendChild(check);

        CellTemplate = new DataTemplate { VisualTree = cell };
        CellStyle = Application.Current?.TryFindResource("SelectCell") as Style;
    }

    private static void OnCellMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<DataGridRow>(sender as DependencyObject) is { } row)
        {
            row.IsSelected = !row.IsSelected;
            e.Handled = true;
        }
    }

    private void OnHeaderLoaded(object sender, RoutedEventArgs e)
    {
        var grid = FindAncestor<DataGrid>(_header);
        if (grid is null || ReferenceEquals(grid, _grid))
            return;

        _grid = grid;
        grid.SelectionChanged += (_, _) => SyncHeader();
        SyncHeader();
    }

    private void OnHeaderChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing || _grid is null)
            return;

        if (_header.IsChecked == true)
            _grid.SelectAll();
        else
            _grid.UnselectAll();
    }

    private void SyncHeader()
    {
        if (_grid is null)
            return;

        var selected = _grid.SelectedItems.Count;
        _syncing = true;
        _header.IsChecked = selected == 0 ? false : selected == _grid.Items.Count ? true : null;
        _syncing = false;
    }

    private static T? FindAncestor<T>(DependencyObject? node) where T : DependencyObject
    {
        while (node is not null and not T)
            node = node is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(node) : LogicalTreeHelper.GetParent(node);
        return node as T;
    }
}
