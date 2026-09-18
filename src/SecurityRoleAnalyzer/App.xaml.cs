using System.Windows;
using System.Windows.Threading;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            ErrorLog.Write("Lỗi không bắt được", args.ExceptionObject as Exception ?? new Exception(args.ExceptionObject?.ToString()));
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            ErrorLog.Write("Task lỗi không được quan sát", args.Exception);
            args.SetObserved();
        };

        Theme.Apply(AppSettings.Current.Theme);
    }

    private static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Dialogs.ShowError(e.Exception, "Lỗi không bắt được trên giao diện");
        e.Handled = true;
    }
}
