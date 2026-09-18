using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SecurityRoleAnalyzer.Services;
using SecurityRoleAnalyzer.ViewModels;
using SecurityRoleAnalyzer.Views;

namespace SecurityRoleAnalyzer.Tests;

/// <summary>
/// Render cửa sổ chính ra file PNG (không chụp màn hình) để xem lại giao diện sáng/tối.
/// Chỉ chạy khi đặt biến môi trường SRA_RENDER=1.
/// </summary>
public class RenderPreview
{
    private static readonly string OutputFolder =
        Environment.GetEnvironmentVariable("SRA_RENDER_DIR") ?? Path.GetTempPath();

    [Fact]
    public void Render_main_window_in_both_themes()
    {
        // Không có gói skip nên bỏ qua im lặng khi không bật cờ.
        if (Environment.GetEnvironmentVariable("SRA_RENDER") != "1")
            return;

        XamlSmokeTests.RunSta(() =>
        {
            XamlSmokeTests.EnsureApp();
            foreach (var theme in new[] { AppTheme.Light, AppTheme.Dark })
            {
                Theme.Apply(theme);
                var window = new MainWindow
                {
                    Width = 1480,
                    Height = 860,
                    WindowStartupLocation = WindowStartupLocation.Manual,
                    Left = -4000,
                    Top = -4000,
                    ShowInTaskbar = false,
                };
                window.Show();
                ((MainViewModel)window.DataContext).LoadDemo();
                Pump();

                var bitmap = new RenderTargetBitmap(1480, 860, 96, 96, PixelFormats.Pbgra32);
                bitmap.Render(window);
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(bitmap));

                var path = Path.Combine(OutputFolder, $"main_{theme}.png");
                using (var stream = File.Create(path))
                    encoder.Save(stream);

                window.Close();
                Assert.True(File.Exists(path));
            }
        });
    }

    /// <summary>Cho Dispatcher xử lý hết hàng đợi để layout và binding hoàn tất trước khi render.</summary>
    private static void Pump()
    {
        for (var i = 0; i < 12; i++)
        {
            System.Windows.Threading.Dispatcher.CurrentDispatcher.Invoke(
                () => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
            Thread.Sleep(60);
        }
    }
}
