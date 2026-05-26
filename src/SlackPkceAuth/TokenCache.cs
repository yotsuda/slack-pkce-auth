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
        var fullPath = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(this, _jsonOptions);

        // 同一ディレクトリの一時ファイルに書き、権限を本人のみに絞ってから
        // アトミックに置換する。途中クラッシュや並行書き込みでの破損を防ぎ、
        // 最終ファイルは生成された時点で本人しか読めない状態になる。
        var tmp = Path.Combine(dir ?? ".", $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(tmp, json);
            RestrictToCurrentUser(tmp);
            File.Move(tmp, fullPath, overwrite: true);
        }
        catch
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best effort */ }
            throw;
        }
    }

    /// <summary>
    /// キャッシュファイルを本人(現在のユーザー)のみアクセス可に制限する。
    /// POSIX は 0600、Windows は継承 ACL を断ち切り現在ユーザーに FullControl のみ付与。
    /// 強化は best-effort — 失敗してもトークン保存自体は失敗させない。
    /// </summary>
    private static void RestrictToCurrentUser(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                RestrictAclWindows(path);
            else
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch { /* best effort */ }
    }

    private static void RestrictAclWindows(string path)
    {
        // managed の ACL API (System.Security.AccessControl) は net9.0 の
        // cross-platform TFM から参照できないため、Windows 標準の icacls を使う。
        // grant 先は現在ユーザーの SID。SID が取れなければ何もしない
        // (誤ったアカウントに付与して本人を締め出すより安全側に倒す)。
        var sid = GetCurrentUserSid();
        if (sid == null) return;

        RunIcacls(path, "/inheritance:r", "/grant:r", $"*{sid}:(F)");
    }

    /// <summary>whoami /user から現在ユーザーの SID (S-1-...) を取得。失敗時は null。</summary>
    private static string? GetCurrentUserSid()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("whoami")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("/user");
            psi.ArgumentList.Add("/fo");
            psi.ArgumentList.Add("csv");
            psi.ArgumentList.Add("/nh");

            using var p = System.Diagnostics.Process.Start(psi);
            if (p == null) return null;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);

            var m = System.Text.RegularExpressions.Regex.Match(output, @"S-1-[0-9-]+");
            return m.Success ? m.Value : null;
        }
        catch { return null; }
    }

    private static void RunIcacls(string path, params string[] args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("icacls")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(path);
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = System.Diagnostics.Process.Start(psi);
        p?.WaitForExit(5000);
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
