using System.Runtime.InteropServices;
using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer;

/// <summary>
/// Điểm vào của ứng dụng. Chạy bình thường thì mở giao diện; có tham số --export-review/--snapshot
/// thì chạy chế độ dòng lệnh rồi thoát (dùng cho báo cáo định kỳ).
/// </summary>
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (!CommandLineRunner.IsHeadless(args))
        {
            var app = new App();
            app.InitializeComponent();
            return app.Run();
        }

        // WinExe không có console sẵn: bám vào console của tiến trình gọi, nếu không thì tạo mới.
        if (!AttachConsole(AttachParentProcess))
            AllocConsole();

        try
        {
            return CommandLineRunner.RunAsync(args).GetAwaiter().GetResult();
        }
        finally
        {
            FreeConsole();
        }
    }

    private const int AttachParentProcess = -1;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();
}
