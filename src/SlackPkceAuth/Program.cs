namespace SlackPkceAuth;

public class Program
{
    public static int Main(string[] args)
    {
        var (options, error, helpRequested, versionRequested) = CliOptions.Parse(args);

        if (helpRequested)
        {
            Console.WriteLine(CliOptions.HelpText);
            return 0;
        }
        if (versionRequested)
        {
            Console.WriteLine($"slack-pkce-auth {PkceFlow.GetVersion()}");
            return 0;
        }
        if (error != null)
        {
            Console.Error.WriteLine($"error: {error}");
            Console.Error.WriteLine("Run with --help for usage.");
            return 2;
        }

        try
        {
            var token = AcquireToken(options!);
            Console.WriteLine(OutputFormatter.Format(token, options!.Output));
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Authentication cancelled.");
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static TokenCache AcquireToken(CliOptions options)
    {
        var log = options.Quiet
            ? new Action<string>(_ => { })
            : new Action<string>(s => Console.Error.WriteLine($"[slack-pkce-auth] {s}"));

        // Cache 経路
        if (!string.IsNullOrEmpty(options.CachePath) && !options.Force)
        {
            var cached = TokenCache.Load(options.CachePath);
            if (cached != null && !string.IsNullOrEmpty(cached.AccessToken))
            {
                if (!cached.IsExpired)
                {
                    log($"Using cached token (TeamId={cached.TeamId ?? "?"}).");
                    return cached;
                }

                log("Cached token has expired.");

                if (options.RefreshIfExpired && cached.HasRefreshToken)
                {
                    try
                    {
                        log("Attempting refresh...");
                        var flow = new PkceFlow(options, log);
                        var refreshed = flow.Refresh(cached.RefreshToken!);
                        var newCache = TokenCache.FromTokenResponse(refreshed);
                        // Slack の rotation: refresh で refresh_token も更新される場合あり
                        // 来なければ既存を保持
                        if (string.IsNullOrEmpty(newCache.RefreshToken))
                            newCache.RefreshToken = cached.RefreshToken;
                        if (string.IsNullOrEmpty(newCache.TeamId)) newCache.TeamId = cached.TeamId;
                        if (string.IsNullOrEmpty(newCache.TeamName)) newCache.TeamName = cached.TeamName;
                        if (string.IsNullOrEmpty(newCache.UserId)) newCache.UserId = cached.UserId;
                        if (string.IsNullOrEmpty(newCache.Scope)) newCache.Scope = cached.Scope;

                        newCache.Save(options.CachePath);
                        log("Refresh successful.");
                        return newCache;
                    }
                    catch (Exception ex)
                    {
                        log($"Refresh failed ({ex.Message}). Falling back to interactive flow.");
                    }
                }
            }
        }

        // Interactive PKCE
        log("Starting PKCE flow.");
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(options.TimeoutMinutes));
        var pkce = new PkceFlow(options, log);
        var response = pkce.Authorize(cts.Token);
        var newToken = TokenCache.FromTokenResponse(response);
        log($"Authorized as user {response.UserId} on team {response.TeamName} ({response.TeamId}).");

        if (!string.IsNullOrEmpty(options.CachePath))
        {
            newToken.Save(options.CachePath);
            log($"Token cached at: {options.CachePath}");
        }

        return newToken;
    }
}
