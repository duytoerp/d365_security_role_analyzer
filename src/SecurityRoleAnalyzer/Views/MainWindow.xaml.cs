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

        var vm = (MainViewModel)DataContext;
        // Ctrl+F: ô tìm kiếm nằm trong view của chế độ đang mở, nên phải tìm trong cây trực quan.
        vm.SearchFocusRequested += () => VisualSearch.FocusSearchBox(ModeContent);

        // Lỗi ghi nhật ký thao tác phải hiện ra, không được im lặng.
        ActionLogStore.WriteFailed += message => Dispatcher.BeginInvoke(() => vm.StatusText = "⚠ " + message);

        if (Environment.GetCommandLineArgs().Contains("--demo", StringComparer.OrdinalIgnoreCase))
            vm.LoadDemo();
    }

    // Mở menu Công cụ ngay dưới nút; ContextMenu không kế thừa DataContext nên gán thủ công.
    private void OnToolsClick(object sender, RoutedEventArgs e)
    {
        if (ToolsButton.ContextMenu is not { } menu)
            return;
        menu.DataContext = DataContext;
        menu.PlacementTarget = ToolsButton;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }
}
