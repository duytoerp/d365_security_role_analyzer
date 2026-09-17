using System.Windows;
using Microsoft.Win32;

namespace SecurityRoleAnalyzer.Views;

public static class Dialogs
{
    private const string Title = "Security Role Analyzer";

    private static Window? Owner => Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive)
                                    ?? Application.Current?.MainWindow;

    public static void ShowError(Exception ex)
    {
        var message = ex.Message;
        for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
        {
            if (!message.Contains(inner.Message, StringComparison.Ordinal))
                message += Environment.NewLine + Environment.NewLine + inner.Message;
        }
        Show(message, MessageBoxImage.Error);
    }

    public static void ShowWarning(string message) => Show(message, MessageBoxImage.Warning);

    public static bool Confirm(string message)
    {
        var owner = Owner;
        var result = owner is null
            ? MessageBox.Show(message, Title, MessageBoxButton.YesNo, MessageBoxImage.Question)
            : MessageBox.Show(owner, message, Title, MessageBoxButton.YesNo, MessageBoxImage.Question);
        return result == MessageBoxResult.Yes;
    }

    public static string? SaveExcel(string fileName)
    {
        var dialog = new SaveFileDialog
        {
            FileName = fileName,
            Filter = "Excel Workbook (*.xlsx)|*.xlsx",
            DefaultExt = ".xlsx",
        };
        return dialog.ShowDialog(Owner) == true ? dialog.FileName : null;
    }

    private static void Show(string message, MessageBoxImage image)
    {
        var owner = Owner;
        if (owner is null)
            MessageBox.Show(message, Title, MessageBoxButton.OK, image);
        else
            MessageBox.Show(owner, message, Title, MessageBoxButton.OK, image);
    }
}
