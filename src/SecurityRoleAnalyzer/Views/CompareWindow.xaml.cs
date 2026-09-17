using System.Windows;
using SecurityRoleAnalyzer.ViewModels;

namespace SecurityRoleAnalyzer.Views;

public partial class CompareWindow : Window
{
    private CompareWindow(CompareViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    public static void Show(Window? owner, CompareViewModel viewModel) =>
        new CompareWindow(viewModel) { Owner = owner }.Show();
}
