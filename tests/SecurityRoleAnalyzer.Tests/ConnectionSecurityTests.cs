using SecurityRoleAnalyzer.Services;

namespace SecurityRoleAnalyzer.Tests;

public class ConnectionSecurityTests
{
    [Theory]
    [InlineData("AuthType=OAuth;Url=http://org.crm5.dynamics.com;AppId=x;RedirectUri=http://localhost")]
    [InlineData("AuthType=ClientSecret;ServiceUri=http://org.crm.dynamics.com;ClientId=x;ClientSecret=y")]
    [InlineData("AuthType=OAuth;url=org.crm.dynamics.com")]
    public void Non_https_environment_urls_are_rejected(string connectionString)
    {
        var ex = Assert.Throws<ArgumentException>(() => ConnectionSecurity.EnsureHttps(connectionString));
        Assert.DoesNotContain("ClientSecret=y", ex.Message);
    }

    [Fact]
    public void Https_urls_and_localhost_redirect_are_allowed()
    {
        // RedirectUri=http://localhost là chuẩn của OAuth native app, không phải địa chỉ môi trường.
        ConnectionSecurity.EnsureHttps("AuthType=OAuth;Url=https://org.crm5.dynamics.com;AppId=x;RedirectUri=http://localhost");
        ConnectionSecurity.EnsureHttps(new ConnectionProfile { Url = "https://org.crm.dynamics.com" }.BuildConnectionString(null, null));
    }

    [Fact]
    public void Malformed_connection_string_error_does_not_echo_its_content()
    {
        var ex = Assert.Throws<ArgumentException>(() => ConnectionSecurity.EnsureHttps("Url=https://a;ClientSecret='abc"));
        Assert.DoesNotContain("abc", ex.Message);
    }

    [Theory]
    [InlineData("AuthType=ClientSecret;Url=https://a;ClientId=1;ClientSecret=S3cr3t~value;RequireNewInstance=true", "S3cr3t~value")]
    [InlineData("Password=\"p@ss; word\";Username=u", "p@ss")]
    [InlineData("{\"client_secret\": \"zzTop\"}", "zzTop")]
    [InlineData("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi")]
    [InlineData("https://login/?access_token=tok123&x=1", "tok123")]
    public void Redact_hides_secret_values(string text, string secret)
    {
        var redacted = ConnectionSecurity.Redact(text);
        Assert.DoesNotContain(secret, redacted);
        Assert.Contains("***", redacted);
    }

    [Fact]
    public void Redact_keeps_ordinary_text_and_token_cache_path()
    {
        const string text = "AuthType=OAuth;Url=https://a;TokenCacheStorePath=C:\\cache;Role Secretary updated";
        Assert.Equal(text, ConnectionSecurity.Redact(text));
    }
}
