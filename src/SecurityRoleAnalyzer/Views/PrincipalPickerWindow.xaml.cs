using System.Windows;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Views;

public partial class PrincipalPickerWindow : Window
{
    private readonly Func<string, Task<List<PrincipalSearchResult>>> _search;
    private readonly string _actionText;

    private PrincipalPickerWindow(string title, Func<string, Task<List<PrincipalSearchResult>>> search,
        string actionText, string? hint, bool searchOnOpen)
    {
        InitializeComponent();
        _search = search;
        _actionText = actionText;
        Title = title;
        HeaderText.Text = title;
        OkButton.Content = actionText;
        if (hint is not null)
            InfoText.Text = hint;
        Loaded += (_, _) =>
        {
            SearchBox.Focus();
            if (searchOnOpen)
                OnSearch(this, new RoutedEventArgs());
        };
    }

    public List<PrincipalSearchResult> Selected { get; private set; } = [];

    /// <param name="actionText">Nội dung nút xác nhận, ví dụ "Gán role", "Thêm vào team".</param>
    /// <param name="searchOnOpen">Tìm ngay khi mở (dùng cho danh sách cục bộ như role).</param>
    public static List<PrincipalSearchResult>? Show(Window? owner, string title, Func<string, Task<List<PrincipalSearchResult>>> search,
        string actionText = "Gán role", string? hint = null, bool searchOnOpen = false)
    {
        var window = new PrincipalPickerWindow(title, search, actionText, hint, searchOnOpen) { Owner = owner };
        return window.ShowDialog() == true ? window.Selected : null;
    }

    private async void OnSearch(object sender, RoutedEventArgs e)
    {
        IsEnabled = false;
        InfoText.Text = "Đang tìm...";
        try
        {
            var results = await _search(SearchBox.Text);
            ResultGrid.ItemsSource = results;
            InfoText.Text = results.Count == 100
                ? "Hiển thị 100 kết quả đầu tiên – hãy nhập từ khóa cụ thể hơn."
                : $"Tìm thấy {results.Count} kết quả.";
        }
        catch (Exception ex)
        {
            InfoText.Text = "Lỗi: " + ex.Message;
        }
        finally
        {
            IsEnabled = true;
            SearchBox.Focus();
        }
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        Selected = ResultGrid.SelectedItems.OfType<PrincipalSearchResult>().ToList();
        if (Selected.Count == 0)
        {
            InfoText.Text = "Hãy chọn ít nhất một dòng.";
            return;
        }

        var names = string.Join("\n", Selected.Take(10).Select(s => "• " + s.Name));
        if (Selected.Count > 10)
            names += $"\n... và {Selected.Count - 10} mục khác";
        if (MessageBox.Show(this, $"{_actionText}: {Selected.Count} mục sau?\n\n{names}", Title,
                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            DialogResult = true;
        }
    }
}
