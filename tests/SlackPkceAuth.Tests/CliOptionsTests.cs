using Xunit;

namespace SlackPkceAuth.Tests;

public class CliOptionsTests
{
    [Fact]
    public void Parse_RequiresClientId()
    {
        var (opts, error, _, _) = CliOptions.Parse(Array.Empty<string>());
        Assert.Null(opts);
        Assert.Contains("--client-id", error);
    }

    [Fact]
    public void Parse_MinimalValid()
    {
        var (opts, error, _, _) = CliOptions.Parse(new[] { "--client-id", "abc" });
        Assert.Null(error);
        Assert.NotNull(opts);
        Assert.Equal("abc", opts!.ClientId);
        Assert.Equal(OutputFormat.Token, opts.Output);
        Assert.False(opts.Quiet);
    }

    [Fact]
    public void Parse_HelpRequested()
    {
        var (_, _, help, _) = CliOptions.Parse(new[] { "--help" });
        Assert.True(help);
    }

    [Fact]
    public void Parse_VersionRequested()
    {
        var (_, _, _, version) = CliOptions.Parse(new[] { "--version" });
        Assert.True(version);
    }

    [Fact]
    public void Parse_AllOptions()
    {
        var (opts, error, _, _) = CliOptions.Parse(new[]
        {
            "--client-id", "cid",
            "--client-secret", "secret",
            "--scopes", "channels:read",
            "--redirect-url", "https://example.com/cb.html",
            "--port", "9999",
            "--output", "json",
            "--cache", "/tmp/t.json",
            "--refresh-if-expired",
            "--timeout", "5",
            "--quiet"
        });
        Assert.Null(error);
        Assert.NotNull(opts);
        Assert.Equal("cid", opts!.ClientId);
        Assert.Equal("secret", opts.ClientSecret);
        Assert.Equal("channels:read", opts.Scopes);
        Assert.Equal("https://example.com/cb.html", opts.RedirectUrl);
        Assert.Equal(9999, opts.Port);
        Assert.Equal(OutputFormat.Json, opts.Output);
        Assert.Equal("/tmp/t.json", opts.CachePath);
        Assert.True(opts.RefreshIfExpired);
        Assert.Equal(5, opts.TimeoutMinutes);
        Assert.True(opts.Quiet);
    }

    [Fact]
    public void Parse_InvalidPort()
    {
        var (_, error, _, _) = CliOptions.Parse(new[] { "--client-id", "x", "--port", "99999" });
        Assert.Contains("port", error);
    }

    [Fact]
    public void Parse_InvalidOutputFormat()
    {
        var (_, error, _, _) = CliOptions.Parse(new[] { "--client-id", "x", "--output", "xml" });
        Assert.Contains("Invalid --output", error);
    }

    [Fact]
    public void Parse_RefreshRequiresCache()
    {
        var (_, error, _, _) = CliOptions.Parse(new[] { "--client-id", "x", "--refresh-if-expired" });
        Assert.Contains("requires --cache", error);
    }

    [Fact]
    public void Parse_UnknownArg()
    {
        var (_, error, _, _) = CliOptions.Parse(new[] { "--client-id", "x", "--bogus" });
        Assert.Contains("Unknown argument", error);
    }

    [Fact]
    public void Parse_DefaultRedirectUrl()
    {
        var (opts, _, _, _) = CliOptions.Parse(new[] { "--client-id", "x" });
        Assert.NotNull(opts);
        Assert.Equal(CliOptions.DefaultRedirectUrl, opts!.EffectiveRedirectUrl);
        Assert.Equal(CliOptions.DefaultPort, opts.EffectivePort);
        Assert.Equal(CliOptions.DefaultScopes, opts.EffectiveScopes);
    }
}
