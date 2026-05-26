using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SlackPkceAuth;

/// <summary>
/// Slack OAuth 2.0 with PKCE フローの実装。
/// SlackDrive の SlackAuthManager から CLI 用に切り出したコア。
/// </summary>
internal class PkceFlow
{
    private readonly CliOptions _options;
    private readonly Action<string> _log;
    private static readonly HttpClient _http = new();

    public PkceFlow(CliOptions options, Action<string> log)
    {
        _options = options;
        _log = log;
    }

    public TokenResponse Authorize(CancellationToken ct = default)
    {
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var state = Guid.NewGuid().ToString("N");

        // 外部リレー経由で既定以外のポートを使う場合、リレーに転送先ポートを伝える
        // ため redirect_uri に relay_port を付与する。authorize と token 交換では
        // 同一の redirect_uri を渡す必要があるので一度だけ構築して使い回す。
        var baseRedirect = _options.EffectiveRedirectUrl;
        var redirectUri = BuildRedirectUri(baseRedirect, _options.EffectivePort, CliOptions.DefaultPort);
        if (redirectUri != baseRedirect)
            _log($"Relay port {_options.EffectivePort} signaled to relay via redirect_uri (relay must forward there).");

        var authUrl = $"https://slack.com/oauth/v2/authorize" +
            $"?client_id={Uri.EscapeDataString(_options.ClientId!)}" +
            $"&user_scope={Uri.EscapeDataString(_options.EffectiveScopes)}" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            $"&state={state}" +
            $"&code_challenge={codeChallenge}" +
            $"&code_challenge_method=S256";
        if (!string.IsNullOrEmpty(_options.Team))
            authUrl += $"&team={Uri.EscapeDataString(_options.Team)}";

        var code = WaitForAuthorizationCode(redirectUri, state, authUrl, ct);
        return ExchangeCodeForToken(code, codeVerifier, redirectUri);
    }

    public TokenResponse Refresh(string refreshToken)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = _options.ClientId!,
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken
        };
        if (!string.IsNullOrEmpty(_options.ClientSecret))
            parameters["client_secret"] = _options.ClientSecret;

        var content = new FormUrlEncodedContent(parameters);
        var response = _http.PostAsync("https://slack.com/api/oauth.v2.access", content)
            .GetAwaiter().GetResult();
        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        return ParseTokenResponse(body, "refresh");
    }

    private string WaitForAuthorizationCode(string redirectUrl, string expectedState, string authUrl, CancellationToken ct)
    {
        var redirectUri = new Uri(redirectUrl);
        string listenerPrefix;
        if (redirectUri.Host != "localhost" && redirectUri.Host != "127.0.0.1")
        {
            listenerPrefix = $"http://localhost:{_options.EffectivePort}/slack/callback/";
        }
        else
        {
            listenerPrefix = $"{redirectUri.Scheme}://{redirectUri.Host}:{redirectUri.Port}{redirectUri.AbsolutePath}";
            if (!listenerPrefix.EndsWith('/')) listenerPrefix += "/";
        }

        using var listener = new HttpListener();
        try
        {
            listener.Prefixes.Add(listenerPrefix);
            listener.Start();
        }
        catch (HttpListenerException ex)
        {
            var port = redirectUri.Host is "localhost" or "127.0.0.1" ? redirectUri.Port : _options.EffectivePort;
            var msg = port <= 1024
                ? $"Failed to bind port {port}. Administrative privileges may be required."
                : $"Failed to bind port {port}. Is another instance running?";
            throw new InvalidOperationException(msg, ex);
        }

        _log($"Listening on {listenerPrefix}");
        _log($"Opening browser: {authUrl}");
        try
        {
            Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _log($"Could not auto-open browser ({ex.Message}). Please open this URL manually:");
            _log(authUrl);
        }

        using var ctReg = ct.Register(() => listener.Stop());

        try
        {
            var context = listener.GetContext();
            var query = context.Request.QueryString;

            var error = query["error"];
            if (!string.IsNullOrEmpty(error))
            {
                SendFailureResponse(context, $"OAuth error: {error}");
                throw new InvalidOperationException($"OAuth error: {error}");
            }

            var state = query["state"];
            if (state != expectedState)
            {
                SendFailureResponse(context, "Invalid state parameter (possible CSRF).");
                throw new InvalidOperationException("Invalid state parameter — possible CSRF.");
            }

            var code = query["code"];
            if (string.IsNullOrEmpty(code))
            {
                SendFailureResponse(context, "No authorization code received.");
                throw new InvalidOperationException("No authorization code received.");
            }

            SendSuccessResponse(context);
            return code;
        }
        catch (HttpListenerException) when (ct.IsCancellationRequested)
        {
            throw new OperationCanceledException("Authentication cancelled.", ct);
        }
        finally
        {
            listener.Close();
        }
    }

    private TokenResponse ExchangeCodeForToken(string code, string codeVerifier, string redirectUri)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = _options.ClientId!,
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = codeVerifier
        };
        if (!string.IsNullOrEmpty(_options.ClientSecret))
            parameters["client_secret"] = _options.ClientSecret;

        var content = new FormUrlEncodedContent(parameters);
        var response = _http.PostAsync("https://slack.com/api/oauth.v2.access", content)
            .GetAwaiter().GetResult();
        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        return ParseTokenResponse(body, "exchange");
    }

    internal static TokenResponse ParseTokenResponse(string body, string operation)
    {
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        if (!root.GetProperty("ok").GetBoolean())
        {
            var error = root.TryGetProperty("error", out var e) ? e.GetString() : "unknown_error";
            throw new InvalidOperationException($"Token {operation} failed: {error}");
        }

        var result = new TokenResponse();

        // User Token は authed_user.access_token に来る (OAuth v2)
        // Refresh response はトップレベルに access_token が来る
        if (root.TryGetProperty("authed_user", out var authedUser) &&
            authedUser.TryGetProperty("access_token", out var userAccess))
        {
            result.AccessToken = userAccess.GetString() ?? "";
            if (authedUser.TryGetProperty("refresh_token", out var rt))
                result.RefreshToken = rt.GetString();
            if (authedUser.TryGetProperty("expires_in", out var ex))
                result.ExpiresIn = ex.GetInt32();
            if (authedUser.TryGetProperty("scope", out var sc))
                result.Scope = sc.GetString();
        }
        else if (root.TryGetProperty("access_token", out var tokenEl))
        {
            result.AccessToken = tokenEl.GetString() ?? "";
            if (root.TryGetProperty("refresh_token", out var rt))
                result.RefreshToken = rt.GetString();
            if (root.TryGetProperty("expires_in", out var ex))
                result.ExpiresIn = ex.GetInt32();
            if (root.TryGetProperty("scope", out var sc))
                result.Scope = sc.GetString();
        }
        else
        {
            throw new InvalidOperationException($"Token {operation}: response did not contain access_token");
        }

        if (root.TryGetProperty("team", out var team))
        {
            if (team.TryGetProperty("id", out var teamId)) result.TeamId = teamId.GetString();
            if (team.TryGetProperty("name", out var teamName)) result.TeamName = teamName.GetString();
        }
        if (root.TryGetProperty("authed_user", out var au) && au.TryGetProperty("id", out var uid))
            result.UserId = uid.GetString();

        return result;
    }

    private void SendSuccessResponse(HttpListenerContext context)
    {
        var html = LoadEmbeddedResource("SlackPkceAuth.Resources.AuthSuccess.html");
        html = html.Replace("{{VERSION}}", GetVersion());
        WriteResponse(context, html, 200);
    }

    private static void SendFailureResponse(HttpListenerContext context, string errorMessage)
    {
        var html = LoadEmbeddedResource("SlackPkceAuth.Resources.AuthFailure.html");
        html = html.Replace("{{ERROR_MESSAGE}}", WebUtility.HtmlEncode(errorMessage));
        html = html.Replace("{{VERSION}}", GetVersion());
        WriteResponse(context, html, 400);
    }

    private static void WriteResponse(HttpListenerContext context, string html, int statusCode)
    {
        var buffer = Encoding.UTF8.GetBytes(html);
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "text/html; charset=UTF-8";
        context.Response.ContentLength64 = buffer.Length;
        context.Response.OutputStream.Write(buffer, 0, buffer.Length);
        context.Response.Close();
    }

    private static string LoadEmbeddedResource(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded resource not found: {resourceName}");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    internal static string GetVersion() =>
        typeof(PkceFlow).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    /// <summary>
    /// Slack に渡す redirect_uri を構築する。外部リレー(loopback 以外)を使い、かつ
    /// 既定以外のリスナーポートを使う場合のみ relay_port クエリを付与してリレーに
    /// 転送先ポートを伝える。localhost 直リダイレクト時はリレーが無く、既定ポート時は
    /// リレー側の既定で足りるため baseUrl をそのまま返す。
    /// authorize と token 交換で同一値を渡す必要があるため純関数として切り出す。
    /// </summary>
    internal static string BuildRedirectUri(string baseUrl, int port, int defaultPort)
    {
        if (port == defaultPort) return baseUrl;
        if (new Uri(baseUrl).IsLoopback) return baseUrl;

        var sep = baseUrl.Contains('?') ? '&' : '?';
        return $"{baseUrl}{sep}relay_port={port}";
    }

    // ── PKCE crypto helpers ──────────────────────────────────────────

    internal static string GenerateCodeVerifier()
    {
        var bytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Base64UrlEncode(bytes);
    }

    internal static string GenerateCodeChallenge(string codeVerifier)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal class TokenResponse
{
    public string AccessToken { get; set; } = "";
    public string? RefreshToken { get; set; }
    public int? ExpiresIn { get; set; }
    public string? Scope { get; set; }
    public string? TeamId { get; set; }
    public string? TeamName { get; set; }
    public string? UserId { get; set; }
}
