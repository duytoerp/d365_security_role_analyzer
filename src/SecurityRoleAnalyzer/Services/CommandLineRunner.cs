using System.IO;
using ClosedXML.Excel;
using SecurityRoleAnalyzer.Models;

namespace SecurityRoleAnalyzer.Services;

/// <summary>
/// Chạy không cần giao diện, dùng cho báo cáo định kỳ hoặc pipeline:
///   SecurityRoleAnalyzer.exe --export-review &lt;file.xlsx&gt; --url &lt;https://org.crm5.dynamics.com&gt;
///                            [--client-id ... --client-secret ...] [--profile "PROD"]
///   SecurityRoleAnalyzer.exe --snapshot &lt;file.json&gt; --url ...
/// Kết quả in ra stdout; mã thoát 0 là thành công.
/// </summary>
public static class CommandLineRunner
{
    public const string ExportReviewOption = "--export-review";
    public const string SnapshotOption = "--snapshot";

    public static bool IsHeadless(string[] args) =>
        args.Any(a => a.Equals(ExportReviewOption, StringComparison.OrdinalIgnoreCase)
                      || a.Equals(SnapshotOption, StringComparison.OrdinalIgnoreCase)
                      || a.Equals("--help", StringComparison.OrdinalIgnoreCase));

    public static async Task<int> RunAsync(string[] args)
    {
        var options = Parse(args);

        if (options.ContainsKey("--help"))
        {
            Console.WriteLine(HelpText);
            return 0;
        }

        try
        {
            var connectionString = BuildConnectionString(options);
            Console.WriteLine("Đang kết nối...");
            using var service = await DataverseService.ConnectAsync(connectionString);
            Console.WriteLine($"Đã kết nối: {service.OrganizationName} ({service.EnvironmentKey}) – {service.CurrentUserName}");

            var progress = new Progress<string>(Console.WriteLine);

            if (options.TryGetValue(ExportReviewOption, out var reviewPath))
                await ExportReviewAsync(service, progress, reviewPath);

            if (options.TryGetValue(SnapshotOption, out var snapshotPath))
                await CaptureSnapshotAsync(service, progress, snapshotPath);

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Lỗi: " + Views.Dialogs.Flatten(ex));
            ErrorLog.Write("Chạy chế độ dòng lệnh", ex);
            return 1;
        }
    }

    private static async Task ExportReviewAsync(DataverseService service, IProgress<string> progress, string path)
    {
        var index = await service.GetAccessIndexAsync(progress);
        var (users, roles) = AccessReviewBuilder.Build(index);

        using var workbook = new XLWorkbook();
        ExcelExporter.AddInfoSheet(workbook, "Tong quan",
        [
            ("Môi trường", service.EnvironmentKey),
            ("Thời điểm", DateTime.Now.ToString("dd/MM/yyyy HH:mm")),
            ("Số user", users.Count),
            ("Số role", roles.Count),
            ("User có cảnh báo", users.Count(u => u.HasIssue)),
            ("Role không được dùng", roles.Count(r => r.IsUnused)),
        ], []);

        ExcelExporter.AddSheet(workbook, "Users", users,
            new ExportColumn<ReviewUserRow>("Họ tên", r => r.User.FullName, 30),
            new ExportColumn<ReviewUserRow>("Username", r => r.User.DomainName, 30),
            new ExportColumn<ReviewUserRow>("Business Unit", r => r.User.BusinessUnitName, 25),
            new ExportColumn<ReviewUserRow>("Trạng thái", r => r.User.StatusText),
            new ExportColumn<ReviewUserRow>("Role trực tiếp", r => r.DirectRoles, 60),
            new ExportColumn<ReviewUserRow>("Role qua team", r => r.TeamRoles, 60),
            new ExportColumn<ReviewUserRow>("Số team", r => r.TeamCount),
            new ExportColumn<ReviewUserRow>("Cảnh báo", r => r.Flags, 40));

        ExcelExporter.AddSheet(workbook, "Roles", roles,
            new ExportColumn<ReviewRoleRow>("Role", r => r.Role.Name, 40),
            new ExportColumn<ReviewRoleRow>("Business Unit", r => r.Role.BusinessUnitName, 25),
            new ExportColumn<ReviewRoleRow>("Managed", r => r.Role.ManagedText),
            new ExportColumn<ReviewRoleRow>("User trực tiếp", r => r.DirectUserCount),
            new ExportColumn<ReviewRoleRow>("Team", r => r.TeamCount),
            new ExportColumn<ReviewRoleRow>("User hiệu lực", r => r.EffectiveUserCount),
            new ExportColumn<ReviewRoleRow>("Không dùng", r => r.IsUnused ? "x" : ""));

        ExcelExporter.AddUserRoleMatrix(workbook, "Ma tran User x Role", index);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        workbook.SaveAs(path);
        Console.WriteLine($"Đã xuất rà soát quyền: {Path.GetFullPath(path)} ({users.Count} user, {roles.Count} role)");
    }

    private static async Task CaptureSnapshotAsync(DataverseService service, IProgress<string> progress, string path)
    {
        var catalog = await service.GetPrivilegeCatalogAsync();
        var index = await service.GetAccessIndexAsync(progress);
        var snapshot = SnapshotService.Create(index, catalog, service.EnvironmentKey, service.CurrentUserName);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        SnapshotService.Save(snapshot, path);
        Console.WriteLine($"Đã lưu snapshot: {Path.GetFullPath(path)} ({snapshot.Roles.Count} role)");
    }

    /// <summary>Lấy thông tin kết nối từ tham số, hoặc từ hồ sơ đã lưu nếu chỉ truyền --profile/--url.</summary>
    private static string BuildConnectionString(Dictionary<string, string> options)
    {
        if (options.TryGetValue("--connection-string", out var raw))
            return raw;

        var profiles = ConnectionProfileStore.Load();
        ConnectionProfile? profile = null;

        if (options.TryGetValue("--profile", out var name))
        {
            profile = profiles.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                      ?? throw new InvalidOperationException($"Không tìm thấy hồ sơ kết nối tên \"{name}\".");
        }
        else if (options.TryGetValue("--url", out var url))
        {
            profile = profiles.FirstOrDefault(p => p.Url.TrimEnd('/').Equals(url.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
                      ?? new ConnectionProfile { Url = url, AuthType = ConnectionAuthType.ClientSecret };
        }

        if (profile is null)
            throw new InvalidOperationException("Thiếu thông tin kết nối: dùng --url, --profile hoặc --connection-string.");

        if (options.TryGetValue("--client-id", out var clientId))
        {
            profile.ClientId = clientId;
            profile.AuthType = ConnectionAuthType.ClientSecret;
        }

        var secret = options.GetValueOrDefault("--client-secret")
                     ?? Environment.GetEnvironmentVariable("SRA_CLIENT_SECRET")
                     ?? profile.GetSecret();

        if (profile.AuthType == ConnectionAuthType.ClientSecret && string.IsNullOrEmpty(secret))
        {
            throw new InvalidOperationException(
                "Chế độ dòng lệnh cần client secret: truyền --client-secret, đặt biến môi trường SRA_CLIENT_SECRET, "
                + "hoặc lưu secret trong hồ sơ kết nối (đăng nhập tương tác không dùng được khi chạy tự động).");
        }

        return profile.BuildConnectionString(secret, null);
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
                continue;
            var value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "";
            options[args[i]] = value;
        }
        return options;
    }

    private const string HelpText = """
        D365 Security Role Analyzer – chế độ dòng lệnh

          --export-review <file.xlsx>   Xuất rà soát quyền toàn hệ thống (User × Role)
          --snapshot <file.json>        Chụp snapshot phân quyền của môi trường

        Kết nối (chọn một):
          --profile "<tên>"             Dùng hồ sơ kết nối đã lưu (kèm secret đã lưu)
          --url <https://org...>        URL môi trường
          --connection-string "<...>"   Connection string đầy đủ

          --client-id <guid>            Application user
          --client-secret <secret>      Hoặc đặt biến môi trường SRA_CLIENT_SECRET

        Ví dụ:
          SecurityRoleAnalyzer.exe --export-review C:\BaoCao\RaSoat.xlsx --profile PROD
        """;
}
