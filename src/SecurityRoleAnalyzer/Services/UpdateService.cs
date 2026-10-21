using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Một bản phát hành mới hơn bản đang chạy, đã chọn đúng bộ cài cho edition hiện tại.</summary>
public sealed record UpdateInfo(
    Version Version, string Title, string Notes, string PageUrl,
    string AssetName, string DownloadUrl, long Size, string? Sha256, string? ChecksumsUrl);

/// <summary>
/// Kiểm tra và cài bản mới từ GitHub Releases. Bộ cài chỉ được chạy khi: tải từ đúng repo qua https,
/// đúng edition (bản Viewer không bao giờ nhận bộ cài Full), mới hơn bản đang chạy, khớp SHA256,
/// và — nếu bản đang chạy có chữ ký số — được ký hợp lệ bởi cùng nhà phát hành.
/// </summary>
public static class UpdateService
{
    public const string Repository = "duytoerp/d365_security_role_analyzer";
    public const string ChecksumsFileName = "SHA256SUMS.txt";

    public static string ReleasesPage => $"https://github.com/{Repository}/releases";
    private static string LatestReleaseApi => $"https://api.github.com/repos/{Repository}/releases/latest";
    private static string DownloadPrefix => $"https://github.com/{Repository}/releases/download/";

    /// <summary>
    /// Tự kiểm tra tối đa khoảng mỗi ngày một lần: API GitHub không xác thực chỉ cho 60 lượt/giờ trên một IP,
    /// và cả công ty thường ra Internet qua chung một IP.
    /// </summary>
    public static readonly TimeSpan AutoCheckInterval = TimeSpan.FromHours(20);

    public static Version CurrentVersion { get; } = Normalize(typeof(UpdateService).Assembly.GetName().Version ?? new Version(0, 0, 0));

    /// <summary>Cài bằng bộ cài (có uninstaller cạnh exe) mới tự cập nhật được; bản portable chỉ mở trang tải.</summary>
    public static bool CanSelfInstall => File.Exists(Path.Combine(AppContext.BaseDirectory, "unins000.exe"));

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        // Proxy công ty thường đòi xác thực Windows. HttpClientHandler không theo redirect từ https xuống http.
        var handler = new HttpClientHandler { DefaultProxyCredentials = CredentialCache.DefaultCredentials };
        var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SecurityRoleAnalyzer", CurrentVersion.ToString(3)));
        return client;
    }

    #region Kiểm tra

    /// <summary>Trả về bản mới hơn bản đang chạy, hoặc null nếu đang dùng bản mới nhất / chưa có bản phát hành nào.</summary>
    public static async Task<UpdateInfo?> CheckAsync(CancellationToken ct = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));

        using var request = new HttpRequestMessage(HttpMethod.Get, LatestReleaseApi);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await Http.SendAsync(request, timeout.Token);

        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;
        if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            throw new InvalidOperationException("GitHub đang tạm giới hạn số lần kiểm tra từ mạng này, hãy thử lại sau ít phút.");
        response.EnsureSuccessStatusCode();

        var release = await response.Content.ReadFromJsonAsync<GitHubRelease>(JsonOptions, timeout.Token)
                      ?? throw new InvalidOperationException("Phản hồi từ GitHub không hợp lệ.");
        return Evaluate(release, CurrentVersion, AppEdition.IsReadOnly);
    }

    /// <summary>Chọn bộ cài phù hợp trong một bản phát hành; null nếu bản đó không mới hơn bản đang chạy.</summary>
    internal static UpdateInfo? Evaluate(GitHubRelease release, Version current, bool viewer)
    {
        if (release.Draft || release.Prerelease || ParseVersion(release.TagName) is not { } version || version <= current)
            return null;

        // So khớp đúng tên, không dùng "chứa": bản Viewer tuyệt đối không được nhận bộ cài Full.
        var expected = SetupAssetName(version, viewer);
        var asset = release.Assets.FirstOrDefault(a => string.Equals(a.Name, expected, StringComparison.OrdinalIgnoreCase))
                    ?? throw new InvalidOperationException($"Bản {version.ToString(3)} chưa có bộ cài {expected} trên GitHub.");
        if (!IsOfficialDownload(asset.BrowserDownloadUrl))
            throw new InvalidOperationException("Đường dẫn tải bộ cài không thuộc repo phát hành chính thức, đã bỏ qua.");

        var sha = asset.Digest is { } digest && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? digest["sha256:".Length..].ToLowerInvariant()
            : null;
        var checksums = release.Assets.FirstOrDefault(a => a.Name == ChecksumsFileName)?.BrowserDownloadUrl;

        return new UpdateInfo(
            version,
            string.IsNullOrWhiteSpace(release.Name) ? release.TagName : release.Name,
            release.Body ?? "",
            release.HtmlUrl.StartsWith($"https://github.com/{Repository}/", StringComparison.Ordinal) ? release.HtmlUrl : ReleasesPage,
            asset.Name, asset.BrowserDownloadUrl, asset.Size, sha,
            checksums is not null && IsOfficialDownload(checksums) ? checksums : null);
    }

    internal static string SetupAssetName(Version version, bool viewer) =>
        $"SecurityRoleAnalyzer{(viewer ? "-Viewer" : "")}-Setup-{version.ToString(3)}.exe";

    private static bool IsOfficialDownload(string url) => url.StartsWith(DownloadPrefix, StringComparison.Ordinal);

    /// <summary>"v3.1.0", "3.1" → 3.1.0; còn lại null.</summary>
    internal static Version? ParseVersion(string? tag) =>
        Version.TryParse(tag?.Trim().TrimStart('v', 'V'), out var version) ? Normalize(version) : null;

    private static Version Normalize(Version v) => new(v.Major, v.Minor, Math.Max(v.Build, 0));

    #endregion

    #region Tải và cài

    /// <summary>Tải bộ cài về thư mục tạm và kiểm tra; trả về đường dẫn file đã kiểm tra xong.</summary>
    public static async Task<string> DownloadAsync(UpdateInfo update, IProgress<int>? progress, CancellationToken ct = default)
    {
        var expectedHash = update.Sha256
                           ?? await ReadChecksumAsync(update, ct)
                           ?? throw new InvalidOperationException("Bản phát hành không có mã SHA256 để kiểm tra bộ cài nên không cài tự động.");

        var folder = Path.Combine(Path.GetTempPath(), "SecurityRoleAnalyzer-Update");
        Directory.CreateDirectory(folder);
        // AssetName đã được so khớp đúng với tên do chính app dựng ở Evaluate, nên không chứa ký tự đường dẫn.
        var path = Path.Combine(folder, update.AssetName);

        using (var response = await Http.GetAsync(update.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            response.EnsureSuccessStatusCode();
            var total = update.Size > 0 ? update.Size : response.Content.Headers.ContentLength ?? 0;
            await using var source = await response.Content.ReadAsStreamAsync(ct);
            await using var target = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
            var buffer = new byte[81920];
            long done = 0;
            int read;
            while ((read = await source.ReadAsync(buffer, ct)) > 0)
            {
                await target.WriteAsync(buffer.AsMemory(0, read), ct);
                done += read;
                if (total > 0)
                    progress?.Report((int)(done * 100 / total));
            }
        }

        try
        {
            Verify(path, expectedHash, Environment.ProcessPath);
        }
        catch
        {
            File.Delete(path);
            throw;
        }
        return path;
    }

    private static async Task<string?> ReadChecksumAsync(UpdateInfo update, CancellationToken ct)
    {
        if (update.ChecksumsUrl is null)
            return null;
        var text = await Http.GetStringAsync(update.ChecksumsUrl, ct);
        return FindChecksum(text, update.AssetName);
    }

    /// <summary>Đọc dòng "&lt;sha256&gt;  &lt;tên file&gt;" (định dạng sha256sum) của đúng file cần tìm.</summary>
    internal static string? FindChecksum(string checksums, string fileName) =>
        checksums.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(parts => parts.Length == 2 && parts[1].TrimStart('*') == fileName && parts[0].Length == 64)
            .Select(parts => parts[0].ToLowerInvariant())
            .FirstOrDefault();

    /// <summary>Kiểm tra SHA256 và, nếu bản đang chạy đã ký số, chữ ký của bộ cài.</summary>
    internal static void Verify(string installerPath, string expectedSha256, string? runningExePath)
    {
        string actual;
        using (var stream = File.OpenRead(installerPath))
            actual = Convert.ToHexStringLower(SHA256.HashData(stream));
        if (!actual.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Bộ cài tải về không khớp mã SHA256 công bố, đã hủy cập nhật.");

        // So theo tên nhà phát hành (không theo thumbprint) để gia hạn chứng chỉ không làm hỏng việc cập nhật;
        // IsTrusted bảo đảm tên đó do một CA được Windows tin cấp.
        if (runningExePath is not null && Authenticode.SignerSubject(runningExePath) is { } publisher
            && (!Authenticode.IsTrusted(installerPath) || Authenticode.SignerSubject(installerPath) != publisher))
        {
            throw new InvalidOperationException("Bộ cài tải về không được ký số bởi cùng nhà phát hành với bản đang dùng, đã hủy cập nhật.");
        }
    }

    /// <summary>
    /// Chạy bộ cài ở chế độ chỉ hiện tiến trình. Inno Setup tự dùng lại kiểu cài lần trước (cho user / cho cả máy),
    /// và tham số /relaunch=1 làm nó mở lại ứng dụng khi cài xong.
    /// </summary>
    public static void StartInstaller(string installerPath) =>
        Process.Start(new ProcessStartInfo(installerPath, "/SILENT /SUPPRESSMSGBOXES /NORESTART /SP- /relaunch=1") { UseShellExecute = true });

    #endregion

    #region Mô hình JSON của GitHub

    internal sealed class GitHubRelease
    {
        public string TagName { get; set; } = "";
        public string? Name { get; set; }
        public string? Body { get; set; }
        public string HtmlUrl { get; set; } = "";
        public bool Draft { get; set; }
        public bool Prerelease { get; set; }
        public List<GitHubAsset> Assets { get; set; } = [];
    }

    internal sealed class GitHubAsset
    {
        public string Name { get; set; } = "";
        public string BrowserDownloadUrl { get; set; } = "";
        public long Size { get; set; }
        /// <summary>GitHub tự tính khi upload, dạng "sha256:&lt;hex&gt;".</summary>
        public string? Digest { get; set; }
    }

    #endregion
}
