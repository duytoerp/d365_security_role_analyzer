using System.Windows;
using System.Windows.Controls;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Views;

/// <summary>Hộp thoại nhập một dòng văn bản.</summary>
public sealed class InputDialog : Window
{
    private readonly TextBox _input;

    private InputDialog(string title, string prompt, string initial)
    {
        Title = title;
        Width = 520;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI");
        FontSize = 13;
        Background = (System.Windows.Media.Brush)Application.Current.FindResource("SurfaceBrush");

        _input = new TextBox { Text = initial, Margin = new Thickness(0, 8, 0, 0) };
        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 90, Style = (Style)Application.Current.FindResource("PrimaryButton") };
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button { Content = "Hủy", IsCancel = true, MinWidth = 90 };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);

        var root = new StackPanel { Margin = new Thickness(18) };
        root.Children.Add(new TextBlock { Text = prompt, TextWrapping = TextWrapping.Wrap });
        root.Children.Add(_input);
        root.Children.Add(buttons);
        Content = root;

        Loaded += (_, _) =>
        {
            _input.Focus();
            _input.SelectAll();
        };
    }

    public static string? Show(Window? owner, string title, string prompt, string initial = "")
    {
        var dialog = new InputDialog(title, prompt, initial) { Owner = owner };
        return dialog.ShowDialog() == true ? dialog._input.Text : null;
    }
}

/// <summary>Chọn những phần quyền sẽ sao chép giữa các user.</summary>
public sealed class CopyAccessWindow : Window
{
    private readonly CheckBox _roles;
    private readonly CheckBox _teams;
    private readonly CheckBox _profiles;
    private readonly CheckBox _removeExtra;

    private CopyAccessWindow(UserAnalysis source, string targetText)
    {
        Title = "Sao chép quyền";
        Width = 620;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI");
        FontSize = 13;
        Background = (System.Windows.Media.Brush)Application.Current.FindResource("SurfaceBrush");

        var manageableTeams = source.Teams.Where(t => t.CanManageMembers).ToList();
        var directProfiles = source.FieldProfiles.Where(p => p.IsDirect).DistinctBy(p => p.ProfileId).ToList();

        static string List(IEnumerable<string> names)
        {
            var list = names.ToList();
            return list.Count == 0 ? "(không có)" : string.Join(", ", list.Take(8)) + (list.Count > 8 ? $", ... (+{list.Count - 8})" : "");
        }

        _roles = new CheckBox { IsChecked = true, Margin = new Thickness(0, 10, 0, 0), Content = new TextBlock { TextWrapping = TextWrapping.Wrap, Text = $"Security role gán trực tiếp ({source.DirectRoles.Count}): {List(source.DirectRoles.Select(r => r.Name))}" } };
        _teams = new CheckBox { IsChecked = true, Margin = new Thickness(0, 8, 0, 0), Content = new TextBlock { TextWrapping = TextWrapping.Wrap, Text = $"Thành viên Owner/Access team ({manageableTeams.Count}): {List(manageableTeams.Select(t => t.Name))}" } };
        _profiles = new CheckBox { IsChecked = true, Margin = new Thickness(0, 8, 0, 0), Content = new TextBlock { TextWrapping = TextWrapping.Wrap, Text = $"Field security profile gán trực tiếp ({directProfiles.Count}): {List(directProfiles.Select(p => p.Name))}" } };
        _removeExtra = new CheckBox { Margin = new Thickness(0, 14, 0, 0), Content = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = (System.Windows.Media.Brush)Application.Current.FindResource("DangerBrush"), Text = "Gỡ những role / team / profile trực tiếp mà user đích đang có nhưng user nguồn không có (đồng bộ hoàn toàn)" } };
        foreach (var box in new[] { _roles, _teams, _profiles, _removeExtra })
            box.VerticalContentAlignment = VerticalAlignment.Top;

        var ok = new Button { Content = "Sao chép", IsDefault = true, MinWidth = 100, Style = (Style)Application.Current.FindResource("PrimaryButton") };
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button { Content = "Hủy", IsCancel = true, MinWidth = 90 };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) };
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);

        var root = new StackPanel { Margin = new Thickness(18) };
        root.Children.Add(new TextBlock { Text = $"Nguồn: {source.User.FullName}", FontWeight = FontWeights.SemiBold, FontSize = 15 });
        root.Children.Add(new TextBlock { Text = $"Đích: {targetText}", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) });
        root.Children.Add(new TextBlock { Text = "Role qua team và field security profile qua team được sao chép bằng cách thêm vào cùng team.", Style = (Style)Application.Current.FindResource("Muted"), Margin = new Thickness(0, 6, 0, 0) });
        root.Children.Add(_roles);
        root.Children.Add(_teams);
        root.Children.Add(_profiles);
        root.Children.Add(_removeExtra);
        root.Children.Add(buttons);
        Content = root;
    }

    public static CopyAccessOptions? Show(Window? owner, UserAnalysis source, string targetText)
    {
        var window = new CopyAccessWindow(source, targetText) { Owner = owner };
        if (window.ShowDialog() != true)
            return null;
        var options = new CopyAccessOptions
        {
            Roles = window._roles.IsChecked == true,
            Teams = window._teams.IsChecked == true,
            FieldProfiles = window._profiles.IsChecked == true,
            RemoveExtra = window._removeExtra.IsChecked == true,
        };
        if (options.RemoveExtra && !Dialogs.Confirm("Bạn đã chọn gỡ quyền thừa ở user đích. Tiếp tục?"))
            return null;
        return options;
    }
}
