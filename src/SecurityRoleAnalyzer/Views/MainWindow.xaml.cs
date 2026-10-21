using System.Windows;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.ViewModels;

namespace SecurityRoleAnalyzer.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        WindowMemory.Attach(this);
        if (AppEdition.IsReadOnly)
            Title += " – " + AppEdition.DisplayName;

        var vm = (MainViewModel)DataContext;
        // Ctrl+F: ô tìm kiếm nằm trong view của chế độ đang mở, nên phải tìm trong cây trực quan.
        vm.SearchFocusRequested += () => VisualSearch.FocusSearchBox(ModeContent);

        // Lỗi ghi nhật ký thao tác phải hiện ra, không được im lặng.
        ActionLogStore.WriteFailed += message => Dispatcher.BeginInvoke(() => vm.StatusText = "⚠ " + message);

        if (Environment.GetCommandLineArgs().Contains("--demo", StringComparer.OrdinalIgnoreCase))
            vm.LoadDemo();
        else if (Application.Current is App)
        {
            // Chờ giao diện mở xong rồi mới kiểm tra, để không làm chậm lúc khởi động. Bỏ qua khi chạy trong test.
            Loaded += async (_, _) =>
            {
                await Task.Delay(TimeSpan.FromSeconds(3));
                await vm.CheckForUpdatesAsync(manual: false);
            };
        }
    }

    // Mở menu Công cụ ngay dưới nút; ContextMenu không kế thừa DataContext nên gán thủ công.
    private void OnToolsClick(object sender, RoutedEventArgs e) => OpenMenu(ToolsButton);

    private void OnRoleActionsClick(object sender, RoutedEventArgs e) => OpenMenu(RoleActionsButton);

    private void OpenMenu(System.Windows.Controls.Button button)
    {
        if (button.ContextMenu is not { } menu)
            return;
        menu.DataContext = DataContext;
        menu.PlacementTarget = button;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }
}
