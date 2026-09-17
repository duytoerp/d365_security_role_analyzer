using System.Windows;
using System.Windows.Threading;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;
    }

    private static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Dialogs.ShowError(e.Exception);
        e.Handled = true;
    }
}
