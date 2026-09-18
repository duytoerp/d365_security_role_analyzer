using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Views;

/// <summary>
/// Hỏi cách áp một định nghĩa role vào môi trường hiện tại: tạo role mới hay ghi đè role đã có,
/// và có thêm role vào các Model-driven App hay không.
/// </summary>
public sealed class RoleImportWindow : Window
{
    private readonly RadioButton _createNew;
    private readonly RadioButton _overwrite;
    private readonly CheckBox _linkApps;
    private readonly SecurityRoleInfo? _existing;

    private RoleImportWindow(RoleDefinition definition, SecurityRoleInfo? existing)
    {
        _existing = existing;
        Title = "Áp định nghĩa role";
        Width = 620;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 13;
        SetResourceReference(BackgroundProperty, "SurfaceBrush");
        SetResourceReference(ForegroundProperty, "TextBrush");

        var root = new StackPanel { Margin = new Thickness(18) };

        root.Children.Add(new TextBlock
        {
            Text = definition.Name,
            FontSize = 17,
            FontWeight = FontWeights.SemiBold,
            TextTrimming = TextTrimming.CharacterEllipsis,
        });
        root.Children.Add(Muted(
            $"Nguồn: {definition.SourceEnvironment} · xuất lúc {definition.ExportedOn:dd/MM/yyyy HH:mm}\n"
            + $"{definition.GrantedCount} privilege · {definition.Apps.Count} Model-driven App · kế thừa: "
            + (definition.IsInherited ? "User + Team" : "Chỉ quyền Team")));

        _createNew = new RadioButton
        {
            Content = "Tạo role mới trong Business Unit gốc",
            Margin = new Thickness(0, 16, 0, 0),
            IsChecked = existing is null,
        };
        root.Children.Add(_createNew);

        _overwrite = new RadioButton
        {
            Content = existing is null
                ? "Ghi đè role đã có (không tìm thấy role trùng tên)"
                : $"Thay toàn bộ privilege của role đang có: \"{existing.Name}\"",
            Margin = new Thickness(0, 8, 0, 0),
            IsEnabled = existing is not null,
            IsChecked = existing is not null,
        };
        root.Children.Add(_overwrite);

        if (existing is not null)
        {
            root.Children.Add(Muted(
                "Toàn bộ privilege hiện tại của role đích sẽ bị thay thế. Privilege được sao lưu trước khi ghi đè "
                + "(hoàn tác được trong Công cụ → Lịch sử thao tác)."));
        }

        _linkApps = new CheckBox
        {
            Content = $"Thêm role vào {definition.Apps.Count} Model-driven App theo định nghĩa",
            Margin = new Thickness(0, 14, 0, 0),
            IsChecked = definition.Apps.Count > 0,
            IsEnabled = definition.Apps.Count > 0,
        };
        root.Children.Add(_linkApps);

        root.Children.Add(Muted(
            "Privilege được khớp theo tên nên mang được sang môi trường khác; privilege của giải pháp "
            + "chưa cài trên môi trường này sẽ bị bỏ qua và liệt kê lại sau khi chạy."));

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 18, 0, 0),
        };
        var cancel = new Button { Content = "Hủy", IsCancel = true, MinWidth = 90 };
        var ok = new Button
        {
            Content = "Áp dụng",
            IsDefault = true,
            MinWidth = 110,
            Margin = new Thickness(8, 0, 0, 0),
            Style = (Style)Application.Current.FindResource("PrimaryButton"),
        };
        ok.Click += (_, _) => DialogResult = true;
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);
        root.Children.Add(buttons);

        Content = root;
    }

    private static TextBlock Muted(string text)
    {
        var block = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
        block.SetResourceReference(TextBlock.ForegroundProperty, "MutedTextBrush");
        return block;
    }

    /// <summary>Trả về null nếu người dùng hủy.</summary>
    public static (Guid? TargetRoleId, bool LinkApps)? Show(Window? owner, RoleDefinition definition, SecurityRoleInfo? existing)
    {
        var window = new RoleImportWindow(definition, existing) { Owner = owner };
        if (window.ShowDialog() != true)
            return null;

        var targetId = window._overwrite.IsChecked == true ? window._existing?.Id : null;
        return (targetId, window._linkApps.IsChecked == true);
    }
}
