using System.Windows;
using Microsoft.Win32;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Views;

public static class Dialogs
{
    private const string Title = "Security Role Analyzer";

    private static Window? Owner => Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive)
                                    ?? Application.Current?.MainWindow;

    public static void ShowError(Exception ex, string context = "")
    {
        ErrorLog.Write(string.IsNullOrEmpty(context) ? "Lỗi" : context, ex);
        ErrorWindow.Show(Owner, Flatten(ex), ex.ToString());
    }

    /// <summary>Gộp message của exception và các inner exception, bỏ phần trùng lặp.</summary>
    public static string Flatten(Exception ex)
    {
        var message = ex.Message;
        for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
        {
            if (!message.Contains(inner.Message, StringComparison.Ordinal))
                message += Environment.NewLine + Environment.NewLine + inner.Message;
        }
        return message;
    }

    public static void ShowWarning(string message) => Show(message, MessageBoxImage.Warning);

    /// <summary>
    /// Đặt nội dung vào clipboard. Clipboard Windows hay bị tiến trình khác giữ nên thử lại vài lần;
    /// trả về false nếu vẫn không đặt được.
    /// </summary>
    public static bool CopyToClipboard(string text)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Clipboard.SetDataObject(text, copy: true);
                return true;
            }
            catch (Exception ex) when (attempt < 4)
            {
                _ = ex;
                Thread.Sleep(60);
            }
            catch (Exception ex)
            {
                ErrorLog.Write("Sao chép vào clipboard", ex);
            }
        }
        return false;
    }

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
