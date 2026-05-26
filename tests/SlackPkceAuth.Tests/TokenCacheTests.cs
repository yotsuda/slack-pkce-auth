using Xunit;

namespace SlackPkceAuth.Tests;

public class TokenCacheTests : IDisposable
{
    private readonly string _tempDir;

    public TokenCacheTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "slack-pkce-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    private string TempFile(string name = "token.json") => Path.Combine(_tempDir, name);

    [Fact]
    public void IsExpired_NullExpiresAt_NeverExpired()
    {
        var c = new TokenCache { AccessToken = "t" };
        Assert.False(c.IsExpired);
    }

    [Fact]
    public void IsExpired_PastExpiry_True()
    {
        var c = new TokenCache
        {
            AccessToken = "t",
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 100
        };
        Assert.True(c.IsExpired);
    }

    [Fact]
    public void IsExpired_FutureExpiry_False()
    {
        var c = new TokenCache
        {
            AccessToken = "t",
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600
        };
        Assert.False(c.IsExpired);
    }

    [Fact]
    public void IsExpired_BufferZone_True()
    {
        // 30 秒後に切れるトークンは「もうすぐ切れる」扱いで expired 判定
        var c = new TokenCache
        {
            AccessToken = "t",
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30
        };
        Assert.True(c.IsExpired);
    }

    [Fact]
    public void Load_NonExistent_ReturnsNull()
    {
        Assert.Null(TokenCache.Load(TempFile("nope.json")));
    }

    [Fact]
    public void Load_MalformedJson_ReturnsNull()
    {
        var path = TempFile();
        File.WriteAllText(path, "{ not valid json");
        Assert.Null(TokenCache.Load(path));
    }

    [Fact]
    public void SaveAndLoad_RoundTrip()
    {
        var path = TempFile();
        var original = new TokenCache
        {
            AccessToken = "xoxp-abc",
            RefreshToken = "xoxe-def",
            ExpiresAt = 1735689600,
            Scope = "channels:read",
            TeamId = "T1",
            TeamName = "Acme",
            UserId = "U1"
        };
        original.Save(path);

        var loaded = TokenCache.Load(path);
        Assert.NotNull(loaded);
        Assert.Equal(original.AccessToken, loaded!.AccessToken);
        Assert.Equal(original.RefreshToken, loaded.RefreshToken);
        Assert.Equal(original.ExpiresAt, loaded.ExpiresAt);
        Assert.Equal(original.Scope, loaded.Scope);
        Assert.Equal(original.TeamId, loaded.TeamId);
        Assert.Equal(original.TeamName, loaded.TeamName);
        Assert.Equal(original.UserId, loaded.UserId);
    }

    [Fact]
    public void Save_CreatesDirectory()
    {
        var path = Path.Combine(_tempDir, "nested", "deep", "token.json");
        var c = new TokenCache { AccessToken = "t" };
        c.Save(path);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Save_OmitsNullProperties()
    {
        var path = TempFile();
        new TokenCache { AccessToken = "xoxp-only" }.Save(path);
        var json = File.ReadAllText(path);
        Assert.DoesNotContain("refresh_token", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"team_id\"", json);
    }

    [Fact]
    public void FromTokenResponse_PreservesAllFields()
    {
        var resp = new TokenResponse
        {
            AccessToken = "xoxp-x",
            RefreshToken = "xoxe-x",
            ExpiresIn = 3600,
            Scope = "channels:read",
            TeamId = "T1",
            TeamName = "Acme",
            UserId = "U1"
        };
        var c = TokenCache.FromTokenResponse(resp);

        Assert.Equal("xoxp-x", c.AccessToken);
        Assert.Equal("xoxe-x", c.RefreshToken);
        Assert.NotNull(c.ExpiresAt);
        // ExpiresAt は now+3600 ± 数秒
        var diff = c.ExpiresAt!.Value - DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.InRange(diff, 3590, 3610);
    }

    [Fact]
    public void FromTokenResponse_NoExpiresIn_LeavesExpiresAtNull()
    {
        var resp = new TokenResponse { AccessToken = "x" };
        var c = TokenCache.FromTokenResponse(resp);
        Assert.Null(c.ExpiresAt);
        Assert.False(c.IsExpired);
    }

    [Fact]
    public void HasRefreshToken_DetectsPresence()
    {
        Assert.False(new TokenCache { AccessToken = "x" }.HasRefreshToken);
        Assert.False(new TokenCache { AccessToken = "x", RefreshToken = "" }.HasRefreshToken);
        Assert.True(new TokenCache { AccessToken = "x", RefreshToken = "y" }.HasRefreshToken);
    }
}
