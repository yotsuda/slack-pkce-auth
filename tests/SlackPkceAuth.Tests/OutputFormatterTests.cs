using System.Text.Json;
using Xunit;

namespace SlackPkceAuth.Tests;

public class OutputFormatterTests
{
    private static TokenCache MakeFull() => new()
    {
        AccessToken = "xoxp-test",
        RefreshToken = "xoxe-test",
        ExpiresAt = 1735689600,
        Scope = "channels:read",
        TeamId = "T1",
        TeamName = "Acme",
        UserId = "U1"
    };

    private static TokenCache MakeMinimal() => new() { AccessToken = "xoxp-only" };

    [Fact]
    public void Token_OutputsAccessTokenOnly()
    {
        Assert.Equal("xoxp-test", OutputFormatter.Format(MakeFull(), OutputFormat.Token));
    }

    [Fact]
    public void Token_Minimal()
    {
        Assert.Equal("xoxp-only", OutputFormatter.Format(MakeMinimal(), OutputFormat.Token));
    }

    [Fact]
    public void Json_FullShape()
    {
        var json = OutputFormatter.Format(MakeFull(), OutputFormat.Json);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("xoxp-test", root.GetProperty("access_token").GetString());
        Assert.Equal("xoxe-test", root.GetProperty("refresh_token").GetString());
        Assert.Equal(1735689600, root.GetProperty("expires_at").GetInt64());
        Assert.Equal("channels:read", root.GetProperty("scope").GetString());
        Assert.Equal("T1", root.GetProperty("team_id").GetString());
        Assert.Equal("Acme", root.GetProperty("team_name").GetString());
        Assert.Equal("U1", root.GetProperty("user_id").GetString());
    }

    [Fact]
    public void Json_MinimalOmitsAbsentFields()
    {
        var json = OutputFormatter.Format(MakeMinimal(), OutputFormat.Json);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("xoxp-only", root.GetProperty("access_token").GetString());
        Assert.False(root.TryGetProperty("refresh_token", out _));
        Assert.False(root.TryGetProperty("expires_at", out _));
        Assert.False(root.TryGetProperty("team_id", out _));
    }

    [Fact]
    public void Env_FullShape()
    {
        var env = OutputFormatter.Format(MakeFull(), OutputFormat.Env);
        Assert.Contains("SLACK_TOKEN=xoxp-test", env);
        Assert.Contains("SLACK_REFRESH_TOKEN=xoxe-test", env);
        Assert.Contains("SLACK_TEAM_ID=T1", env);
        Assert.Contains("SLACK_USER_ID=U1", env);
    }

    [Fact]
    public void Env_MinimalOnlyHasToken()
    {
        var env = OutputFormatter.Format(MakeMinimal(), OutputFormat.Env);
        Assert.Equal("SLACK_TOKEN=xoxp-only", env);
    }

    [Fact]
    public void DotnetSecret_FullShape()
    {
        var output = OutputFormatter.Format(MakeFull(), OutputFormat.DotnetSecret);
        Assert.Contains("dotnet user-secrets set Slack:Token \"xoxp-test\"", output);
        Assert.Contains("dotnet user-secrets set Slack:RefreshToken \"xoxe-test\"", output);
        Assert.Contains("dotnet user-secrets set Slack:TeamId \"T1\"", output);
    }

    [Fact]
    public void DotnetSecret_EscapesQuotesInToken()
    {
        var token = new TokenCache { AccessToken = "xoxp-with-\"quote\"" };
        var output = OutputFormatter.Format(token, OutputFormat.DotnetSecret);
        Assert.Contains("\"xoxp-with-\\\"quote\\\"\"", output);
    }
}
