using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace SlackPkceAuth.Tests;

public class PkceFlowTests
{
    [Fact]
    public void GenerateCodeVerifier_IsBase64Url()
    {
        var v = PkceFlow.GenerateCodeVerifier();
        Assert.DoesNotContain("=", v);
        Assert.DoesNotContain("+", v);
        Assert.DoesNotContain("/", v);
        // 64 bytes → 86 base64 chars unpadded
        Assert.Equal(86, v.Length);
    }

    [Fact]
    public void GenerateCodeVerifier_IsRandom()
    {
        var a = PkceFlow.GenerateCodeVerifier();
        var b = PkceFlow.GenerateCodeVerifier();
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void GenerateCodeChallenge_IsSha256OfVerifierBase64Url()
    {
        var verifier = "abcDEF123_-";
        var challenge = PkceFlow.GenerateCodeChallenge(verifier);

        // 期待値: SHA256(verifier as UTF-8) → base64url(no padding)
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(verifier));
        var expected = Convert.ToBase64String(hash)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.Equal(expected, challenge);
    }

    [Fact]
    public void GenerateCodeChallenge_DeterministicForSameInput()
    {
        var verifier = "test_verifier_abc";
        Assert.Equal(
            PkceFlow.GenerateCodeChallenge(verifier),
            PkceFlow.GenerateCodeChallenge(verifier));
    }

    // ── BuildRedirectUri ─────────────────────────────────────────────

    [Fact]
    public void BuildRedirectUri_DefaultPort_ReturnsBaseUnchanged()
    {
        var baseUrl = "https://yotsuda.github.io/SlackDrive/oauth/callback.html";
        Assert.Equal(baseUrl, PkceFlow.BuildRedirectUri(baseUrl, 8765, 8765));
    }

    [Fact]
    public void BuildRedirectUri_ExternalRelay_NonDefaultPort_AppendsRelayPort()
    {
        var baseUrl = "https://yotsuda.github.io/SlackDrive/oauth/callback.html";
        Assert.Equal(baseUrl + "?relay_port=9000", PkceFlow.BuildRedirectUri(baseUrl, 9000, 8765));
    }

    [Fact]
    public void BuildRedirectUri_ExistingQuery_UsesAmpersand()
    {
        var baseUrl = "https://relay.example.com/cb.html?foo=bar";
        Assert.Equal(baseUrl + "&relay_port=9000", PkceFlow.BuildRedirectUri(baseUrl, 9000, 8765));
    }

    [Fact]
    public void BuildRedirectUri_LocalhostRedirect_NoRelayPort()
    {
        // localhost 直リダイレクトはリレーが無いので relay_port を付けない
        var baseUrl = "http://localhost:9000/slack/callback/";
        Assert.Equal(baseUrl, PkceFlow.BuildRedirectUri(baseUrl, 9000, 8765));
    }

    [Fact]
    public void BuildRedirectUri_LoopbackIp_NoRelayPort()
    {
        var baseUrl = "http://127.0.0.1:9000/slack/callback/";
        Assert.Equal(baseUrl, PkceFlow.BuildRedirectUri(baseUrl, 9000, 8765));
    }

    // ── ParseTokenResponse ───────────────────────────────────────────

    [Fact]
    public void ParseTokenResponse_UserToken_FromAuthedUser()
    {
        var json = """
        {
          "ok": true,
          "authed_user": {
            "id": "U0123",
            "access_token": "xoxp-test",
            "refresh_token": "xoxe-test",
            "expires_in": 43200,
            "scope": "channels:read"
          },
          "team": { "id": "T0123", "name": "Acme" }
        }
        """;
        var r = PkceFlow.ParseTokenResponse(json, "exchange");
        Assert.Equal("xoxp-test", r.AccessToken);
        Assert.Equal("xoxe-test", r.RefreshToken);
        Assert.Equal(43200, r.ExpiresIn);
        Assert.Equal("channels:read", r.Scope);
        Assert.Equal("U0123", r.UserId);
        Assert.Equal("T0123", r.TeamId);
        Assert.Equal("Acme", r.TeamName);
    }

    [Fact]
    public void ParseTokenResponse_RefreshResponse_TopLevelAccessToken()
    {
        var json = """
        {
          "ok": true,
          "access_token": "xoxp-new",
          "refresh_token": "xoxe-new",
          "expires_in": 43200,
          "scope": "channels:read"
        }
        """;
        var r = PkceFlow.ParseTokenResponse(json, "refresh");
        Assert.Equal("xoxp-new", r.AccessToken);
        Assert.Equal("xoxe-new", r.RefreshToken);
        Assert.Equal(43200, r.ExpiresIn);
    }

    [Fact]
    public void ParseTokenResponse_NotOk_ThrowsWithError()
    {
        var json = """{ "ok": false, "error": "invalid_grant" }""";
        var ex = Assert.Throws<InvalidOperationException>(
            () => PkceFlow.ParseTokenResponse(json, "exchange"));
        Assert.Contains("invalid_grant", ex.Message);
        Assert.Contains("exchange", ex.Message);
    }

    [Fact]
    public void ParseTokenResponse_NoAccessToken_Throws()
    {
        var json = """{ "ok": true }""";
        var ex = Assert.Throws<InvalidOperationException>(
            () => PkceFlow.ParseTokenResponse(json, "exchange"));
        Assert.Contains("did not contain access_token", ex.Message);
    }
}
