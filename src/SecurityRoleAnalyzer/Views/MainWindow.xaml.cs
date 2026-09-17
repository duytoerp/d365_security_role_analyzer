using System.Windows;
using SecurityRoleAnalyzer.ViewModels;

namespace SecurityRoleAnalyzer.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        if (Environment.GetCommandLineArgs().Contains("--demo", StringComparer.OrdinalIgnoreCase))
            ((MainViewModel)DataContext).LoadDemo();
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
