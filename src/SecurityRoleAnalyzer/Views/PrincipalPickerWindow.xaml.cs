using System.Windows;
using SecurityRoleAnalyzer.Models;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Views;

public partial class PrincipalPickerWindow : Window
{
    private readonly Func<string, int, Task<List<PrincipalSearchResult>>> _search;
    private readonly string _actionText;

    /// <summary>Giới hạn kết quả hiện tại; nút "Tải thêm" nhân đôi giới hạn rồi tìm lại.</summary>
    private int _limit = DataverseService.DefaultSearchTop;

    private PrincipalPickerWindow(string title, Func<string, int, Task<List<PrincipalSearchResult>>> search,
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
    public static List<PrincipalSearchResult>? Show(Window? owner, string title, Func<string, int, Task<List<PrincipalSearchResult>>> search,
        string actionText = "Gán role", string? hint = null, bool searchOnOpen = false)
    {
        var window = new PrincipalPickerWindow(title, search, actionText, hint, searchOnOpen) { Owner = owner };
        return window.ShowDialog() == true ? window.Selected : null;
    }

    /// <summary>Dạng rút gọn cho danh sách cục bộ (không cần giới hạn số dòng).</summary>
    public static List<PrincipalSearchResult>? Show(Window? owner, string title, Func<string, Task<List<PrincipalSearchResult>>> search,
        string actionText = "Gán role", string? hint = null, bool searchOnOpen = false) =>
        Show(owner, title, (text, _) => search(text), actionText, hint, searchOnOpen);

    private void OnSearch(object sender, RoutedEventArgs e)
    {
        _limit = DataverseService.DefaultSearchTop;
        _ = RunSearchAsync();
    }

    private void OnLoadMore(object sender, RoutedEventArgs e)
    {
        _limit *= 4;
        _ = RunSearchAsync();
    }

    private async Task RunSearchAsync()
    {
        IsEnabled = false;
        InfoText.Text = "Đang tìm...";
        try
        {
            var results = await _search(SearchBox.Text, _limit);
            ResultGrid.ItemsSource = results;

            var truncated = results.Count >= _limit;
            LoadMoreButton.Visibility = truncated ? Visibility.Visible : Visibility.Collapsed;
            InfoText.Text = results.Count == 0
                ? "Không có kết quả nào khớp. Thử từ khóa khác."
                : truncated
                    ? $"Hiển thị {results.Count} kết quả đầu tiên – nhập từ khóa cụ thể hơn, hoặc bấm \"Tải thêm\"."
                    : $"Tìm thấy {results.Count} kết quả.";
        }
        catch (Exception ex)
        {
            InfoText.Text = "Lỗi: " + ex.Message;
            ErrorLog.Write("Tìm user/team", ex);
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
