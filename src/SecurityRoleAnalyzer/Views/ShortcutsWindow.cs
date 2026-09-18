using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SecurityRoleAnalyzer.Views;

/// <summary>Bảng phím tắt (F1).</summary>
public sealed class ShortcutsWindow : Window
{
    private static readonly (string Key, string Action)[] Shortcuts =
    [
        ("F1", "Mở bảng phím tắt này"),
        ("F5", "Làm mới dữ liệu (xóa cache)"),
        ("Ctrl + F", "Chuyển con trỏ về ô tìm kiếm"),
        ("Ctrl + S", "Lưu thay đổi privilege đang sửa"),
        ("Ctrl + E", "Xuất Excel"),
        ("Ctrl + K", "Mở hộp thoại kết nối"),
        ("Ctrl + Shift + C", "Chép tên và Id của mục đang chọn"),
        ("Ctrl + C", "Chép các dòng đang chọn trong bảng"),
        ("Ctrl + L", "Tra cứu ngược: ai có quyền X"),
        ("Ctrl + H", "Lịch sử thao tác & hoàn tác"),
        ("Ctrl + 1…6", "Chuyển chế độ: Roles, Teams, Users, Apps, Field Security, Business Units"),
        ("Enter / Space", "Trên ô chọn: bật/tắt chọn dòng"),
        ("+ / -", "Trên ô quyền (chế độ sửa): nâng / hạ mức quyền"),
        ("Double-click", "Mở role / team / user / app tương ứng"),
    ];

    private ShortcutsWindow()
    {
        Title = "Phím tắt";
        Width = 560;
        SizeToContent = SizeToContent.Height;
        MaxHeight = 640;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 13;
        SetResourceReference(BackgroundProperty, "SurfaceBrush");
        SetResourceReference(ForegroundProperty, "TextBrush");

        var grid = new Grid { Margin = new Thickness(18) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        for (var i = 0; i <= Shortcuts.Length; i++)
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        for (var i = 0; i < Shortcuts.Length; i++)
        {
            var (key, action) = Shortcuts[i];

            var keyText = new TextBlock
            {
                Text = key,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12.5,
                Margin = new Thickness(0, 4, 12, 4),
                VerticalAlignment = VerticalAlignment.Center,
            };
            keyText.SetResourceReference(TextBlock.ForegroundProperty, "PrimaryBrush");
            Grid.SetRow(keyText, i);
            grid.Children.Add(keyText);

            var actionText = new TextBlock
            {
                Text = action,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 4),
                VerticalAlignment = VerticalAlignment.Center,
            };
            actionText.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
            Grid.SetRow(actionText, i);
            Grid.SetColumn(actionText, 1);
            grid.Children.Add(actionText);
        }

        var close = new Button
        {
            Content = "Đóng",
            IsDefault = true,
            IsCancel = true,
            MinWidth = 90,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 16, 0, 0),
            Style = (Style)Application.Current.FindResource("PrimaryButton"),
        };
        close.Click += (_, _) => Close();
        Grid.SetRow(close, Shortcuts.Length);
        Grid.SetColumnSpan(close, 2);
        grid.Children.Add(close);

        Content = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = grid };
    }

    public static void Show(Window? owner) => new ShortcutsWindow { Owner = owner }.ShowDialog();
}
