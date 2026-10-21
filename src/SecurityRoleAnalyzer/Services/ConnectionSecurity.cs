using System.Data.Common;
using System.Text.RegularExpressions;

namespace SecurityRoleAnalyzer.Services;

/// <summary>Kiểm tra kết nối có an toàn không, và che bí mật trước khi ghi log hoặc hiển thị lỗi.</summary>
public static partial class ConnectionSecurity
{
    /// <summary>Các khóa mà ServiceClient chấp nhận cho địa chỉ môi trường.</summary>
    private static readonly string[] UrlKeys = ["Url", "ServiceUri", "Service Uri", "Server"];

    /// <summary>
    /// Bearer token được gửi tới URL môi trường, nên chỉ cho phép https:// để token không đi trên kênh không mã hóa.
    /// Áp dụng cho mọi kiểu kết nối, kể cả connection string dán tay và chế độ dòng lệnh.
    /// </summary>
    public static void EnsureHttps(string connectionString)
    {
        DbConnectionStringBuilder builder;
        try
        {
            builder = new DbConnectionStringBuilder { ConnectionString = connectionString };
        }
        catch (ArgumentException)
        {
            // Không kèm exception gốc: thông báo của nó có thể trích lại một phần connection string.
            throw new ArgumentException("Connection string không đúng định dạng.");
        }

        foreach (var key in UrlKeys)
        {
            if (!builder.TryGetValue(key, out var value) || value?.ToString()?.Trim() is not { Length: > 0 } url)
                continue;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException($"URL môi trường phải bắt đầu bằng https:// (đang là \"{Redact(url)}\").");
        }
    }

    /// <summary>Thay giá trị secret, password, token trong chuỗi bằng ***.</summary>
    public static string Redact(string text) =>
        string.IsNullOrEmpty(text)
            ? text
            : BearerPattern().Replace(SecretPattern().Replace(text, "${key}***"), "Bearer ***");

    // "ClientSecret=...", "Password=...", "client_secret": "...", "access_token=..." — giá trị kết thúc ở ; & dấu cách hoặc dấu nháy.
    [GeneratedRegex("""(?<key>\b(?:Client\s?Secret|client_secret|Password|Pwd|Secret|Token|access_token|refresh_token|id_token)\b"?\s*[=:]\s*)(?<value>"[^"]*"|'[^']*'|[^;&\s,"']+)""",
        RegexOptions.IgnoreCase)]
    private static partial Regex SecretPattern();

    [GeneratedRegex(@"\bBearer\s+[A-Za-z0-9\-._~+/]+=*", RegexOptions.IgnoreCase)]
    private static partial Regex BearerPattern();
}
