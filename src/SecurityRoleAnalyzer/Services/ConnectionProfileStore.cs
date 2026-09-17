using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurityRoleAnalyzer.Services;

public enum ConnectionAuthType
{
    OAuthInteractive,
    ClientSecret,
    ConnectionString,
}

/// <summary>Thông tin kết nối được lưu lại. Client secret chỉ được lưu khi người dùng chọn, và được mã hóa bằng DPAPI.</summary>
public sealed class ConnectionProfile
{
    /// <summary>App Id mẫu do Microsoft cung cấp cho công cụ phát triển.</summary>
    public const string DefaultAppId = "51f81489-12ee-4a9e-aaae-a2591f45987d";
    public const string DefaultRedirectUri = "http://localhost";

    /// <summary>Tên hiển thị tùy chọn, ví dụ "PROD", "UAT".</summary>
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public ConnectionAuthType AuthType { get; set; } = ConnectionAuthType.OAuthInteractive;
    public string UserName { get; set; } = "";
    public string AppId { get; set; } = DefaultAppId;
    public string RedirectUri { get; set; } = DefaultRedirectUri;
    public string ClientId { get; set; } = "";
    public DateTime LastUsed { get; set; }
    /// <summary>Client secret mã hóa DPAPI (CurrentUser), base64.</summary>
    public string EncryptedSecret { get; set; } = "";

    [JsonIgnore]
    public string DisplayName => !string.IsNullOrWhiteSpace(Name)
        ? $"{Name} – {Url}"
        : string.IsNullOrWhiteSpace(Url) ? "(connection string)" : Url;

    [JsonIgnore]
    public bool HasSavedSecret => !string.IsNullOrEmpty(EncryptedSecret);

    /// <summary>Có thể kết nối ngay không cần mở hộp thoại.</summary>
    [JsonIgnore]
    public bool CanQuickConnect => AuthType == ConnectionAuthType.OAuthInteractive || (AuthType == ConnectionAuthType.ClientSecret && HasSavedSecret);

    public void SetSecret(string? secret) =>
        EncryptedSecret = string.IsNullOrEmpty(secret)
            ? ""
            : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), null, DataProtectionScope.CurrentUser));

    public string? GetSecret()
    {
        if (!HasSavedSecret)
            return null;
        try
        {
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(EncryptedSecret), null, DataProtectionScope.CurrentUser));
        }
        catch
        {
            return null;
        }
    }

    public override string ToString() => DisplayName;

    public string BuildConnectionString(string? clientSecret, string? rawConnectionString)
    {
        switch (AuthType)
        {
            case ConnectionAuthType.ClientSecret:
                Require(Url, "URL môi trường");
                Require(ClientId, "Client Id");
                Require(clientSecret, "Client Secret");
                return $"AuthType=ClientSecret;Url={Url.Trim()};ClientId={ClientId.Trim()};ClientSecret={clientSecret};RequireNewInstance=true";

            case ConnectionAuthType.ConnectionString:
                Require(rawConnectionString, "Connection string");
                return rawConnectionString!.Trim();

            default:
                Require(Url, "URL môi trường");
                var tokenCache = Path.Combine(ConnectionProfileStore.AppDataFolder, "TokenCache");
                var appId = string.IsNullOrWhiteSpace(AppId) ? DefaultAppId : AppId.Trim();
                var redirect = string.IsNullOrWhiteSpace(RedirectUri) ? DefaultRedirectUri : RedirectUri.Trim();
                var cs = $"AuthType=OAuth;Url={Url.Trim()};AppId={appId};RedirectUri={redirect};LoginPrompt=Auto;RequireNewInstance=true;TokenCacheStorePath={tokenCache}";
                if (!string.IsNullOrWhiteSpace(UserName))
                    cs += $";Username={UserName.Trim()}";
                return cs;
        }
    }

    private static void Require(string? value, string label)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException($"Vui lòng nhập {label}.");
    }
}

public static class ConnectionProfileStore
{
    public static string AppDataFolder { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecurityRoleAnalyzer");

    private static string FilePath => Path.Combine(AppDataFolder, "connections.json");

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static List<ConnectionProfile> Load()
    {
        try
        {
            if (!File.Exists(FilePath))
                return [];
            var profiles = JsonSerializer.Deserialize<List<ConnectionProfile>>(File.ReadAllText(FilePath), Options) ?? [];
            return profiles.OrderByDescending(p => p.LastUsed).ToList();
        }
        catch
        {
            return [];
        }
    }

    public static void Save(ConnectionProfile profile)
    {
        if (profile.AuthType == ConnectionAuthType.ConnectionString)
            return;

        try
        {
            Directory.CreateDirectory(AppDataFolder);
            var profiles = Load();
            profiles.RemoveAll(p => string.Equals(p.Url.TrimEnd('/'), profile.Url.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)
                                    && p.AuthType == profile.AuthType);
            profile.LastUsed = DateTime.Now;
            profiles.Insert(0, profile);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(profiles.Take(15).ToList(), Options));
        }
        catch
        {
            // Lưu lịch sử kết nối là tính năng phụ.
        }
    }
}
