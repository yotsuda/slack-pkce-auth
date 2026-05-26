using System.Text.Json;
using System.Text.Json.Serialization;

namespace SlackPkceAuth;

/// <summary>
/// トークンキャッシュ JSON ファイルの I/O。
/// 形式は出力フォーマット json と同じ shape。
/// </summary>
internal class TokenCache
{
    public string AccessToken { get; set; } = "";
    public string? RefreshToken { get; set; }

    /// <summary>UTC unix epoch seconds。expires_in が無ければ null。</summary>
    public long? ExpiresAt { get; set; }

    public string? Scope { get; set; }
    public string? TeamId { get; set; }
    public string? TeamName { get; set; }
    public string? UserId { get; set; }

    [JsonIgnore]
    public bool IsExpired
    {
        get
        {
            if (ExpiresAt == null) return false;
            // 60 秒のバッファを取って早めに refresh
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60 >= ExpiresAt.Value;
        }
    }

    [JsonIgnore]
    public bool HasRefreshToken => !string.IsNullOrEmpty(RefreshToken);

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static TokenCache? Load(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<TokenCache>(json, _jsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public void Save(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(this, _jsonOptions);
        File.WriteAllText(path, json);

        // POSIX でファイルパーミッションを 600 に
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch { /* best effort */ }
        }
    }

    public static TokenCache FromTokenResponse(TokenResponse response)
    {
        return new TokenCache
        {
            AccessToken = response.AccessToken,
            RefreshToken = response.RefreshToken,
            ExpiresAt = response.ExpiresIn.HasValue
                ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() + response.ExpiresIn.Value
                : null,
            Scope = response.Scope,
            TeamId = response.TeamId,
            TeamName = response.TeamName,
            UserId = response.UserId
        };
    }
}
