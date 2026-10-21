using System.IO;
using System.Security.Cryptography;
using SecurityRoleAnalyzer.Services;
using static SecurityRoleAnalyzer.Services.UpdateService;

namespace SecurityRoleAnalyzer.Tests;

public class UpdateServiceTests
{
    private const string Download = "https://github.com/duytoerp/d365_security_role_analyzer/releases/download/v3.1.0/";
    private static readonly Version Current = new(3, 0, 0);

    private static GitHubRelease Release(string tag = "v3.1.0", params string[] assets) => new()
    {
        TagName = tag,
        Name = "D365 Security Role Analyzer 3.1.0",
        Body = "Sửa lỗi",
        HtmlUrl = "https://github.com/duytoerp/d365_security_role_analyzer/releases/tag/" + tag,
        Assets = (assets.Length > 0 ? assets : ["SecurityRoleAnalyzer-Setup-3.1.0.exe", "SecurityRoleAnalyzer-Viewer-Setup-3.1.0.exe"])
            .Select(name => new GitHubAsset { Name = name, BrowserDownloadUrl = Download + name, Size = 10, Digest = "sha256:" + new string('A', 64) })
            .ToList(),
    };

    [Theory]
    [InlineData(false, "SecurityRoleAnalyzer-Setup-3.1.0.exe")]
    [InlineData(true, "SecurityRoleAnalyzer-Viewer-Setup-3.1.0.exe")]
    public void Each_edition_gets_its_own_installer(bool viewer, string expected)
    {
        var update = Evaluate(Release(), Current, viewer)!;
        Assert.Equal(expected, update.AssetName);
        Assert.Equal(new Version(3, 1, 0), update.Version);
        Assert.Equal(new string('a', 64), update.Sha256);
    }

    [Fact]
    public void Viewer_never_falls_back_to_the_full_installer()
    {
        var release = Release(assets: "SecurityRoleAnalyzer-Setup-3.1.0.exe");
        Assert.Throws<InvalidOperationException>(() => Evaluate(release, Current, viewer: true));
    }

    [Theory]
    [InlineData("v3.0.0")]
    [InlineData("v2.9.9")]
    [InlineData("not-a-version")]
    public void Same_older_or_unparseable_versions_are_not_updates(string tag) =>
        Assert.Null(Evaluate(Release(tag), Current, viewer: false));

    [Fact]
    public void Prereleases_and_drafts_are_ignored()
    {
        var pre = Release();
        pre.Prerelease = true;
        var draft = Release();
        draft.Draft = true;
        Assert.Null(Evaluate(pre, Current, false));
        Assert.Null(Evaluate(draft, Current, false));
    }

    [Fact]
    public void Download_urls_outside_the_official_repo_are_rejected()
    {
        var release = Release();
        release.Assets.ForEach(a => a.BrowserDownloadUrl = "https://github.com/attacker/repo/releases/download/v3.1.0/" + a.Name);
        Assert.Throws<InvalidOperationException>(() => Evaluate(release, Current, false));
    }

    [Fact]
    public void Release_page_from_elsewhere_falls_back_to_the_releases_page()
    {
        var release = Release();
        release.HtmlUrl = "file:///C:/Windows/System32/calc.exe";
        Assert.Equal(ReleasesPage, Evaluate(release, Current, false)!.PageUrl);
    }

    [Theory]
    [InlineData("v3.1", "3.1.0")]
    [InlineData("3.1.2", "3.1.2")]
    [InlineData(" V4.0.0 ", "4.0.0")]
    public void Tags_are_parsed_to_three_part_versions(string tag, string expected) =>
        Assert.Equal(Version.Parse(expected), ParseVersion(tag));

    [Fact]
    public void Checksum_is_read_for_the_exact_file_only()
    {
        var hash = new string('b', 64);
        var text = $"{new string('c', 64)}  SecurityRoleAnalyzer-Setup-3.1.0.exe\n{hash.ToUpperInvariant()} *SecurityRoleAnalyzer-Viewer-Setup-3.1.0.exe\n";
        Assert.Equal(hash, FindChecksum(text, "SecurityRoleAnalyzer-Viewer-Setup-3.1.0.exe"));
        Assert.Null(FindChecksum(text, "SecurityRoleAnalyzer-Viewer-Setup-3.1.1.exe"));
    }

    [Fact]
    public void Authenticode_reads_signed_and_unsigned_files()
    {
        // Tiến trình test chạy bằng dotnet.exe/testhost.exe do Microsoft ký số.
        var signed = Environment.ProcessPath!;
        Assert.Contains("Microsoft", Authenticode.SignerSubject(signed));
        Assert.True(Authenticode.IsTrusted(signed));

        var unsigned = Path.GetTempFileName();
        try
        {
            File.WriteAllText(unsigned, "không có chữ ký");
            Assert.Null(Authenticode.SignerSubject(unsigned));
            Assert.False(Authenticode.IsTrusted(unsigned));

            // Bản đang chạy có chữ ký thì bộ cài không chữ ký phải bị từ chối, dù SHA256 khớp.
            var hash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(unsigned)));
            Assert.Throws<InvalidOperationException>(() => Verify(unsigned, hash, runningExePath: signed));
        }
        finally
        {
            File.Delete(unsigned);
        }
    }

    [Fact]
    public void Verify_rejects_a_tampered_installer()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "bộ cài thật");
            var good = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
            Verify(path, good, runningExePath: null);

            File.AppendAllText(path, " + mã độc");
            Assert.Throws<InvalidOperationException>(() => Verify(path, good, runningExePath: null));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
