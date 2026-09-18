using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Views;

/// <summary>
/// Nhớ vị trí và kích thước cửa sổ giữa các lần mở ứng dụng, lưu trong settings.json theo tên cửa sổ.
/// </summary>
public static class WindowMemory
{
    public static void Attach(Window window, string? name = null)
    {
        var key = name ?? window.GetType().Name;

        window.SourceInitialized += (_, _) =>
        {
            if (AppSettings.Current.PlacementOf(key) is not { IsValid: true } placement)
                return;

            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.Width = placement.Width;
            window.Height = placement.Height;
            window.Left = placement.Left;
            window.Top = placement.Top;
            EnsureOnScreen(window);
            if (placement.Maximized)
                window.WindowState = System.Windows.WindowState.Maximized;
        };

        window.Closing += (_, _) =>
        {
            var maximized = window.WindowState == System.Windows.WindowState.Maximized;
            // RestoreBounds giữ kích thước trước khi phóng to; khi cửa sổ đang bình thường nó rỗng.
            var bounds = maximized ? window.RestoreBounds : new Rect(window.Left, window.Top, window.Width, window.Height);
            if (double.IsNaN(bounds.Width) || bounds.Width <= 0)
                return;

            AppSettings.Current.Remember(key, new WindowPlacement
            {
                Left = bounds.Left,
                Top = bounds.Top,
                Width = bounds.Width,
                Height = bounds.Height,
                Maximized = maximized,
            });
        };
    }

    /// <summary>Màn hình có thể đã đổi độ phân giải hoặc bị tháo; kéo cửa sổ về vùng nhìn thấy được.</summary>
    private static void EnsureOnScreen(Window window)
    {
        var width = SystemParameters.VirtualScreenWidth;
        var height = SystemParameters.VirtualScreenHeight;
        var left = SystemParameters.VirtualScreenLeft;
        var top = SystemParameters.VirtualScreenTop;

        if (window.Left < left || window.Left + 200 > left + width)
            window.Left = left + Math.Max(0, (width - window.Width) / 2);
        if (window.Top < top || window.Top + 100 > top + height)
            window.Top = top + Math.Max(0, (height - window.Height) / 2);
    }
}

/// <summary>Tìm control trong cây trực quan.</summary>
public static class VisualSearch
{
    public static T? FirstOfType<T>(DependencyObject? root, Func<T, bool>? predicate = null) where T : DependencyObject
    {
        if (root is null)
            return null;

        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T typed && (predicate is null || predicate(typed)))
                return typed;
            if (FirstOfType(child, predicate) is { } found)
                return found;
        }
        return null;
    }

    /// <summary>Ô tìm kiếm đầu tiên đang hiển thị trong phần nội dung (dùng cho Ctrl+F).</summary>
    public static void FocusSearchBox(DependencyObject? root)
    {
        var box = FirstOfType<TextBox>(root, t => t.IsVisible && t.Tag is string tag && tag.Contains("Tìm", StringComparison.OrdinalIgnoreCase));
        if (box is null)
            return;
        box.Focus();
        box.SelectAll();
        Keyboard.Focus(box);
    }
}
