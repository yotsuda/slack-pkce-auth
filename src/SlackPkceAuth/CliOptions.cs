namespace SlackPkceAuth;

/// <summary>
/// CLI フラグのパースとバリデーション。--help / --version は別途 Program.cs でハンドル。
/// </summary>
internal class CliOptions
{
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Scopes { get; set; }
    public string? RedirectUrl { get; set; }
    public string? Team { get; set; }
    public int? Port { get; set; }
    public OutputFormat Output { get; set; } = OutputFormat.Token;
    public string? CachePath { get; set; }
    public bool RefreshIfExpired { get; set; }
    public bool Quiet { get; set; }
    public int TimeoutMinutes { get; set; } = 3;
    public bool Force { get; set; }

    public const string DefaultRedirectUrl = "https://yotsuda.github.io/SlackDrive/oauth/callback.html";
    public const int DefaultPort = 8765;
    public const string DefaultScopes =
        "channels:read channels:history " +
        "groups:read groups:history " +
        "im:read im:history mpim:read mpim:history " +
        "users:read files:read chat:write " +
        "search:read search:read.public search:read.private " +
        "search:read.im search:read.mpim search:read.files search:read.users";

    public string EffectiveRedirectUrl => RedirectUrl ?? DefaultRedirectUrl;
    public int EffectivePort => Port ?? DefaultPort;
    public string EffectiveScopes => Scopes ?? DefaultScopes;

    public static (CliOptions? options, string? error, bool helpRequested, bool versionRequested) Parse(string[] args)
    {
        var opts = new CliOptions();

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "-h":
                case "--help":
                    return (null, null, true, false);
                case "--version":
                    return (null, null, false, true);

                case "--client-id":
                    if (++i >= args.Length) return (null, "--client-id requires a value", false, false);
                    opts.ClientId = args[i];
                    break;
                case "--client-secret":
                    if (++i >= args.Length) return (null, "--client-secret requires a value", false, false);
                    opts.ClientSecret = args[i];
                    break;
                case "--scopes":
                    if (++i >= args.Length) return (null, "--scopes requires a value", false, false);
                    opts.Scopes = args[i];
                    break;
                case "--redirect-url":
                    if (++i >= args.Length) return (null, "--redirect-url requires a value", false, false);
                    opts.RedirectUrl = args[i];
                    break;
                case "--team":
                    if (++i >= args.Length) return (null, "--team requires a value", false, false);
                    opts.Team = args[i];
                    break;
                case "--port":
                    if (++i >= args.Length) return (null, "--port requires a value", false, false);
                    if (!int.TryParse(args[i], out var p) || p < 1 || p > 65535)
                        return (null, $"Invalid port: {args[i]}", false, false);
                    opts.Port = p;
                    break;
                case "--output":
                    if (++i >= args.Length) return (null, "--output requires a value", false, false);
                    opts.Output = args[i].ToLowerInvariant() switch
                    {
                        "token" => OutputFormat.Token,
                        "json" => OutputFormat.Json,
                        "env" => OutputFormat.Env,
                        "dotnet-secret" => OutputFormat.DotnetSecret,
                        _ => OutputFormat.Invalid
                    };
                    if (opts.Output == OutputFormat.Invalid)
                        return (null, $"Invalid --output value: {args[i]} (expected: token|json|env|dotnet-secret)", false, false);
                    break;
                case "--cache":
                    if (++i >= args.Length) return (null, "--cache requires a value", false, false);
                    opts.CachePath = args[i];
                    break;
                case "--refresh-if-expired":
                    opts.RefreshIfExpired = true;
                    break;
                case "--quiet":
                case "-q":
                    opts.Quiet = true;
                    break;
                case "--force":
                case "-f":
                    opts.Force = true;
                    break;
                case "--timeout":
                    if (++i >= args.Length) return (null, "--timeout requires a value", false, false);
                    if (!int.TryParse(args[i], out var t) || t < 1 || t > 60)
                        return (null, $"Invalid timeout: {args[i]} (expected: 1-60 minutes)", false, false);
                    opts.TimeoutMinutes = t;
                    break;
                default:
                    return (null, $"Unknown argument: {a}", false, false);
            }
        }

        if (string.IsNullOrEmpty(opts.ClientId))
            return (null, "--client-id is required", false, false);

        if (opts.RefreshIfExpired && string.IsNullOrEmpty(opts.CachePath))
            return (null, "--refresh-if-expired requires --cache", false, false);

        return (opts, null, false, false);
    }

    public const string HelpText = """
slack-pkce-auth — Acquire a Slack User Token (xoxp-) via OAuth 2.0 PKCE.

Usage:
  slack-pkce-auth --client-id <id> [options]

Required:
  --client-id <id>         Slack App Client ID (from api.slack.com/apps)

Optional:
  --client-secret <secret> Slack App Client Secret. Required only if your app
                           is "confidential" (default for new Slack apps).
                           Also required for refresh-token rotation.
  --scopes <scopes>        Space-separated User Token Scopes.
                           Default: comprehensive read+write+search set.
  --redirect-url <url>     OAuth redirect URL pre-registered in your Slack App.
                           Default: https://yotsuda.github.io/SlackDrive/oauth/callback.html
                           (re-uses the SlackDrive relay; safe due to PKCE).
  --team <id-or-domain>    Pre-select workspace by team ID (Txxxxx) or
                           subdomain (acme). Forces routing to that workspace
                           regardless of which workspace is currently active in
                           the browser. Useful to avoid
                           "invalid_team_for_non_distributed_app".
  --port <port>            Local listener port. Default: 8765. With an external
                           relay, the chosen port is signaled to the relay via a
                           relay_port query param, so the relay must support it
                           (the bundled relay/callback.html and the default
                           SlackDrive relay both do).
  --output <format>        token | json | env | dotnet-secret. Default: token.
                             token         = print xoxp- to stdout
                             json          = full token response as JSON
                             env           = SLACK_TOKEN=xoxp-...\nSLACK_REFRESH_TOKEN=...
                             dotnet-secret = `dotnet user-secrets set` commands
  --cache <path>           Persist token to JSON file. Subsequent runs read it.
  --refresh-if-expired     With --cache: silently refresh using refresh_token
                           if access_token has expired. Falls back to interactive
                           flow if refresh fails.
  --force, -f              Ignore --cache and always run interactive flow.
  --timeout <minutes>      Auth flow timeout. Default: 3 (range: 1-60).
  --quiet, -q              Suppress progress messages on stderr.
  --help, -h               Show this help.
  --version                Show version.

Examples:
  # Interactive PKCE flow (browser opens), token to stdout
  slack-pkce-auth --client-id 1234567890.1234567890

  # For korotovsky/slack-mcp-server
  export SLACK_MCP_XOXP_TOKEN=$(slack-pkce-auth --client-id $CID --quiet)

  # Cache + auto-refresh for daemons
  slack-pkce-auth --client-id $CID --client-secret $SECRET \\
                  --cache ~/.slack/token.json --refresh-if-expired --quiet

  # JSON output for scripting
  slack-pkce-auth --client-id $CID --output json | jq -r .access_token
""";
}

internal enum OutputFormat
{
    Token,
    Json,
    Env,
    DotnetSecret,
    Invalid
}
