using System.Text;
using System.Text.Json;

namespace SlackPkceAuth;

internal static class OutputFormatter
{
    private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };

    public static string Format(TokenCache token, OutputFormat format) => format switch
    {
        OutputFormat.Token => token.AccessToken,
        OutputFormat.Json => FormatJson(token),
        OutputFormat.Env => FormatEnv(token),
        OutputFormat.DotnetSecret => FormatDotnetSecret(token),
        _ => throw new ArgumentException($"Unsupported output format: {format}")
    };

    private static string FormatJson(TokenCache token)
    {
        // 互換性のため、CLI 出力では snake_case で出す (Slack API 準拠)
        var obj = new Dictionary<string, object?>
        {
            ["access_token"] = token.AccessToken,
        };
        if (token.RefreshToken != null) obj["refresh_token"] = token.RefreshToken;
        if (token.ExpiresAt != null) obj["expires_at"] = token.ExpiresAt;
        if (!string.IsNullOrEmpty(token.Scope)) obj["scope"] = token.Scope;
        if (!string.IsNullOrEmpty(token.TeamId)) obj["team_id"] = token.TeamId;
        if (!string.IsNullOrEmpty(token.TeamName)) obj["team_name"] = token.TeamName;
        if (!string.IsNullOrEmpty(token.UserId)) obj["user_id"] = token.UserId;

        return JsonSerializer.Serialize(obj, _jsonOptions);
    }

    private static string FormatEnv(TokenCache token)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"SLACK_TOKEN={token.AccessToken}");
        if (!string.IsNullOrEmpty(token.RefreshToken))
            sb.AppendLine($"SLACK_REFRESH_TOKEN={token.RefreshToken}");
        if (!string.IsNullOrEmpty(token.TeamId))
            sb.AppendLine($"SLACK_TEAM_ID={token.TeamId}");
        if (!string.IsNullOrEmpty(token.UserId))
            sb.AppendLine($"SLACK_USER_ID={token.UserId}");
        return sb.ToString().TrimEnd('\r', '\n');
    }

    private static string FormatDotnetSecret(TokenCache token)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"dotnet user-secrets set Slack:Token {Quote(token.AccessToken)}");
        if (!string.IsNullOrEmpty(token.RefreshToken))
            sb.AppendLine($"dotnet user-secrets set Slack:RefreshToken {Quote(token.RefreshToken!)}");
        if (!string.IsNullOrEmpty(token.TeamId))
            sb.AppendLine($"dotnet user-secrets set Slack:TeamId {Quote(token.TeamId!)}");
        return sb.ToString().TrimEnd('\r', '\n');
    }

    private static string Quote(string value) => $"\"{value.Replace("\"", "\\\"")}\"";
}
