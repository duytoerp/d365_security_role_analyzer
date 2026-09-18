using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Views;

/// <summary>
/// Hộp thoại lỗi có thể sao chép được: thông báo ngắn ở trên, chi tiết kỹ thuật (stack trace) mở rộng bên dưới,
/// kèm nút sao chép và mở file log. MessageBox thường không cho copy nên rất khó báo lỗi lại.
/// </summary>
public sealed class ErrorWindow : Window
{
    private ErrorWindow(string message, string detail)
    {
        Title = "Lỗi – Security Role Analyzer";
        Width = 640;
        SizeToContent = SizeToContent.Height;
        MaxHeight = 700;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 13;
        Background = (Brush)Application.Current.FindResource("SurfaceBrush");

        var root = new StackPanel { Margin = new Thickness(18) };

        var header = new StackPanel { Orientation = Orientation.Horizontal };
        header.Children.Add(new TextBlock
        {
            Text = "⛔",
            FontSize = 22,
            Margin = new Thickness(0, 0, 10, 0),
            VerticalAlignment = VerticalAlignment.Top,
        });
        header.Children.Add(new TextBox
        {
            Text = message,
            IsReadOnly = true,
            BorderThickness = new Thickness(0),
            Background = Brushes.Transparent,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 560,
        });
        root.Children.Add(header);

        var details = new TextBox
        {
            Text = detail,
            IsReadOnly = true,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            Height = 220,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 11.5,
            Margin = new Thickness(0, 8, 0, 0),
        };
        root.Children.Add(new Expander
        {
            Header = "Chi tiết kỹ thuật",
            Margin = new Thickness(0, 14, 0, 0),
            Content = details,
        });

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 16, 0, 0),
        };

        var copy = new Button { Content = "📋 Sao chép", MinWidth = 110, Margin = new Thickness(0, 0, 8, 0) };
        copy.Click += (_, _) =>
        {
            if (Dialogs.CopyToClipboard($"{message}{Environment.NewLine}{Environment.NewLine}{detail}"))
                copy.Content = "✔ Đã chép";
        };
        buttons.Children.Add(copy);

        var openLog = new Button { Content = "📂 Mở log", MinWidth = 100, Margin = new Thickness(0, 0, 8, 0) };
        openLog.Click += (_, _) => OpenLog();
        buttons.Children.Add(openLog);

        var close = new Button
        {
            Content = "Đóng",
            IsDefault = true,
            IsCancel = true,
            MinWidth = 90,
            Style = (Style)Application.Current.FindResource("PrimaryButton"),
        };
        close.Click += (_, _) => Close();
        buttons.Children.Add(close);

        root.Children.Add(buttons);
        Content = root;
    }

    public static void Show(Window? owner, string message, string detail)
    {
        // Không dùng ShowDialog khi chưa có cửa sổ nào (lỗi lúc khởi động).
        var window = new ErrorWindow(message, detail) { Owner = owner };
        if (owner is null)
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        window.ShowDialog();
    }

    private static void OpenLog()
    {
        try
        {
            if (!File.Exists(ErrorLog.FilePath))
                ErrorLog.Write("Mở log", "(chưa có lỗi nào được ghi)");
            Process.Start(new ProcessStartInfo(ErrorLog.FilePath) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ErrorLog.Write("Mở file log", ex);
        }
    }
}
