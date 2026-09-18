using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using SecurityRoleAnalyzer.Converters;

namespace SecurityRoleAnalyzer.Controls;

/// <summary>ViewModel hỗ trợ chỉnh sửa mức quyền trực tiếp trên lưới (click để đổi mức).</summary>
public interface IPrivilegeEditHost
{
    bool IsEditingPrivileges { get; }

    /// <summary>Đổi mức quyền của ô: <paramref name="row"/> là dòng dữ liệu, <paramref name="cellPath"/> là CellPath của cột.</summary>
    void CycleDepth(object row, string cellPath, bool backward);
}

/// <summary>
/// Cột DataGrid hiển thị mức quyền dưới dạng ký hiệu màu, bind tới một PrivilegeCell hoặc PrivilegeDepth.
/// Nếu DataContext của lưới là <see cref="IPrivilegeEditHost"/> đang ở chế độ sửa: click trái = mức kế tiếp, click phải = mức trước.
/// </summary>
public sealed class DepthColumn : DataGridTemplateColumn
{
    private static readonly FontFamily SymbolFont = new("Segoe UI Symbol");

    public DepthColumn()
    {
        Width = new DataGridLength(72);
        CanUserSort = true;
        CellStyle = BuildCellStyle();
    }

    /// <summary>Bàn phím: +/Space nâng mức, -/Backspace hạ mức, để không chỉ dùng được bằng chuột.</summary>
    private Style BuildCellStyle()
    {
        var style = new Style(typeof(DataGridCell), Application.Current?.TryFindResource(typeof(DataGridCell)) as Style);
        style.Setters.Add(new EventSetter(UIElement.PreviewKeyDownEvent, new KeyEventHandler(OnCellKeyDown)));
        return style;
    }

    private void OnCellKeyDown(object sender, KeyEventArgs e)
    {
        var backward = e.Key switch
        {
            Key.Add or Key.OemPlus or Key.Space => false,
            Key.Subtract or Key.OemMinus or Key.Back => true,
            _ => (bool?)null,
        };
        if (backward is null || sender is not DataGridCell { DataContext: { } row })
            return;

        if (FindGrid(sender as DependencyObject) is DataGrid { DataContext: IPrivilegeEditHost { IsEditingPrivileges: true } host })
        {
            host.CycleDepth(row, CellPath, backward.Value);
            e.Handled = true;
        }
    }

    /// <summary>Đường dẫn binding tới thuộc tính PrivilegeCell/PrivilegeDepth của dòng.</summary>
    public string CellPath
    {
        get;
        set
        {
            field = value;
            BuildTemplate();
        }
    } = "";

    /// <summary>true nếu CellPath trỏ tới PrivilegeCell (có tooltip và SortKey).</summary>
    public bool IsPrivilegeCell
    {
        get;
        set
        {
            field = value;
            BuildTemplate();
        }
    } = true;

    /// <summary>
    /// Đường dẫn tới cờ "đã sửa" của dòng, dùng để tô nền ô. Chỉ đặt khi dòng thực sự có thuộc tính này;
    /// để trống thì ô không tô nền (tránh binding hỏng ở các lưới chỉ đọc).
    /// </summary>
    public string ChangedPath
    {
        get;
        set
        {
            field = value;
            BuildTemplate();
        }
    } = "";

    private void BuildTemplate()
    {
        var path = CellPath;
        if (string.IsNullOrEmpty(path))
            return;

        var border = new FrameworkElementFactory(typeof(Border));
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(3));
        border.SetValue(FrameworkElement.MarginProperty, new Thickness(-6, 1, -6, 1));
        var changedPath = IsPrivilegeCell ? path + ".IsChanged" : ChangedPath;
        if (!string.IsNullOrEmpty(changedPath))
        {
            border.SetBinding(Border.BackgroundProperty, new Binding(changedPath)
            {
                Converter = ChangedBrushConverter.Instance,
                FallbackValue = Brushes.Transparent,
            });
        }
        border.AddHandler(UIElement.MouseLeftButtonUpEvent, new MouseButtonEventHandler((s, e) => OnCellClick(s, e, false)));
        border.AddHandler(UIElement.MouseRightButtonUpEvent, new MouseButtonEventHandler((s, e) => OnCellClick(s, e, true)));

        var text = new FrameworkElementFactory(typeof(TextBlock));
        text.SetBinding(TextBlock.TextProperty, new Binding(path) { Converter = DepthGlyphConverter.Instance });
        text.SetBinding(TextBlock.ForegroundProperty, new Binding(path) { Converter = DepthBrushConverter.Instance });
        text.SetValue(TextBlock.FontFamilyProperty, SymbolFont);
        text.SetValue(TextBlock.FontSizeProperty, 17.0);
        text.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        text.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);

        if (IsPrivilegeCell)
        {
            border.SetBinding(FrameworkElement.ToolTipProperty, new Binding(path + ".ToolTip"));
            SortMemberPath = path + ".SortKey";
        }
        else
        {
            SortMemberPath = path;
        }

        border.AppendChild(text);
        CellTemplate = new DataTemplate { VisualTree = border };
    }

    private void OnCellClick(object sender, MouseButtonEventArgs e, bool backward)
    {
        if (sender is not FrameworkElement element || element.DataContext is null)
            return;

        if (FindGrid(element) is DataGrid { DataContext: IPrivilegeEditHost { IsEditingPrivileges: true } host })
        {
            host.CycleDepth(element.DataContext, CellPath, backward);
            e.Handled = true;
        }
    }

    private static DataGrid? FindGrid(DependencyObject? node)
    {
        while (node is not null and not DataGrid)
            node = VisualTreeHelper.GetParent(node);
        return node as DataGrid;
    }
}
