using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SecurityRoleAnalyzer.Models;
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

    [Fact]
    public void Render_form_role_window()
    {
        if (Environment.GetEnvironmentVariable("SRA_RENDER") != "1")
            return;

        XamlSmokeTests.RunSta(() =>
        {
            XamlSmokeTests.EnsureApp();
            Theme.Apply(AppTheme.Light);

            var main = new MainViewModel();
            main.LoadDemo();
            var rows = FormRoleAnalyzer.Build(SampleForms(), SampleDirectory());
            var vm = new FormRoleViewModel(main) { RowsView = new ListCollectionView(rows) };
            vm.SummaryCards.Add(new SummaryCard("Form & dashboard", rows.Count.ToString(), "7 loại gán được role"));
            vm.SummaryCards.Add(new SummaryCard("Gán role cụ thể", "5", "Specific security roles"));
            vm.SummaryCards.Add(new SummaryCard("Mở cho mọi role", "1", "Everyone"));
            vm.SummaryCards.Add(new SummaryCard("Không đọc được", "1", "displayconditions hỏng"));

            var window = new FormRoleWindow
            {
                DataContext = vm,
                Width = 1320,
                Height = 800,
                WindowStartupLocation = WindowStartupLocation.Manual,
                Left = -4000,
                Top = -4000,
                ShowInTaskbar = false,
            };
            window.Show();
            vm.SelectedRow = vm.RowsView?.Cast<FormRoleRow>().FirstOrDefault(r => r.RoleCount > 0);
            Pump();

            var bitmap = new RenderTargetBitmap(1320, 800, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(window);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));

            var path = Path.Combine(OutputFolder, "form_roles.png");
            using (var stream = File.Create(path))
                encoder.Save(stream);

            window.Close();
            Assert.True(File.Exists(path));
        });
    }

    private static RoleDirectory SampleDirectory()
    {
        var sales = new Guid("11111111-1111-1111-1111-111111111111");
        var service = new Guid("22222222-2222-2222-2222-222222222222");
        var marketing = new Guid("33333333-3333-3333-3333-333333333333");

        return new RoleDirectory
        {
            Roots =
            [
                new SecurityRoleInfo { Id = sales, Name = "VUS - Sales Manager", BusinessUnitName = "VUS" },
                new SecurityRoleInfo { Id = service, Name = "VUS - Customer Service", BusinessUnitName = "VUS" },
                new SecurityRoleInfo { Id = marketing, Name = "VUS - Marketing", BusinessUnitName = "VUS" },
            ],
            CopyToRoot = new Dictionary<Guid, Guid> { [sales] = sales, [service] = service, [marketing] = marketing },
        };
    }

    private static List<DataverseService.FormInfo> SampleForms()
    {
        var sales = new Guid("11111111-1111-1111-1111-111111111111");
        var service = new Guid("22222222-2222-2222-2222-222222222222");
        var marketing = new Guid("33333333-3333-3333-3333-333333333333");

        return
        [
            new(Guid.NewGuid(), "Lead", "lead", 2, false, 1, [sales, service, marketing], false),
            new(Guid.NewGuid(), "Lead - MKT", "lead", 2, false, 1, [marketing], false),
            new(Guid.NewGuid(), "Lead - OVS", "lead", 2, false, 1, [sales], false),
            new(Guid.NewGuid(), "Information", "lead", 7, true, 1, [], true),
            new(Guid.NewGuid(), "Account", "account", 2, true, 1, [], true),
            new(Guid.NewGuid(), "Contact", "contact", 2, false, 1, [service], false),
            new(Guid.NewGuid(), "Sales Dashboard", "none", 0, false, 1, [sales], false),
            new(Guid.NewGuid(), "Opportunity", "opportunity", 2, false, 1, [], false, true),
        ];
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
