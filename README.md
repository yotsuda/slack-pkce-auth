# slack-pkce-auth

A tiny CLI that runs OAuth 2.0 PKCE against Slack and prints a User Token (`xoxp-`) to stdout. **No backend required** — a static GitHub Pages page relays the OAuth callback, so there's no server for you to run.

Designed to plug in front of any tool that wants a Slack user token: [korotovsky/slack-mcp-server](https://github.com/korotovsky/slack-mcp-server), the official Slack MCP plugin, custom scripts, etc.

## What it does — and what you still need

You **do** need to create a Slack App once (that's where the Client ID comes from). You **don't** need to hand-configure scopes or copy a token out of the web UI.

The usual way to get an `xoxp-` token is:

1. Create a Slack App at api.slack.com/apps
2. Paste 15+ scope strings into the **OAuth & Permissions** page &nbsp;← tedious
3. Click **Install to Workspace**
4. Copy the `xoxp-…` token from the UI &nbsp;← manual
5. Paste it into your `.env` / config &nbsp;← manual

`slack-pkce-auth` collapses steps 2–5 into a single command: scopes are sent at request time, the browser flow runs automatically, and the token is printed to stdout.

> **It cannot remove app creation.** OAuth requires a registered `client_id`. If you can't create or install a Slack app at all (e.g. workspace admin approval is blocked), use browser session tokens instead — see [When to use this](#when-to-use-this).

## When to use this

This tool gives you a **durable** `xoxp-` user token (with optional refresh).

- **Use this** if you can create a Slack app and want a stable token that survives browser logout.
- **Use browser tokens (`xoxc` / `xoxd`)** — e.g. slack-mcp-server's "stealth mode" — if you can't create an app or want zero setup. The trade-off: they're harvested from your logged-in browser session (DevTools) and expire when that session rotates (hours to days), so you re-harvest often.

## Install

```sh
dotnet tool install -g Yotsuda.SlackPkceAuth
```

Or build from source:

```sh
git clone https://github.com/yotsuda/slack-pkce-auth
cd slack-pkce-auth
dotnet pack src/SlackPkceAuth -c Release
dotnet tool install -g --add-source ./src/SlackPkceAuth/nupkg Yotsuda.SlackPkceAuth
```

## Setup (one-time, per Slack App)

1. Create a Slack App at https://api.slack.com/apps → **From scratch**
2. **OAuth & Permissions → Redirect URLs** → add:
   ```
   https://yotsuda.github.io/SlackDrive/oauth/callback.html
   ```
   *(or host this repo's `relay/callback.html` on your own GitHub Pages and use that URL)*
3. Copy the **Client ID** from **Basic Information**

Scopes are passed at request time — no manual scope configuration needed.

### Client secret: only for "confidential" apps

New Slack apps are **confidential** by default and require `--client-secret`.

To drop the secret, make your app a **public client** by enabling **PKCE** in the app settings. Then `--client-id` alone is enough.

> Enabling PKCE is a **one-way switch** (the app becomes a public client permanently), and refresh tokens then **expire after 30 days** instead of lasting indefinitely.

## Usage

```sh
slack-pkce-auth --client-id 1234567890.1234567890
```

A browser opens. After you authorize, the token is printed:

```
xoxp-1234-5678-...
```

### With korotovsky/slack-mcp-server

```sh
export SLACK_MCP_XOXP_TOKEN=$(slack-pkce-auth --client-id $CID --quiet)
slack-mcp-server
```

### With the official Slack MCP plugin / Docker tools

```sh
slack-pkce-auth --client-id $CID --output env > .env
docker run --env-file .env some-slack-tool
```

### Cache + auto-refresh (for daemons)

```sh
slack-pkce-auth --client-id $CID \
                --cache ~/.slack/token.json --refresh-if-expired --quiet
```

First run opens a browser. Subsequent runs read the cached token; if it has expired and a `refresh_token` exists, it refreshes silently (no browser).

> A **confidential** app also needs `--client-secret` here. A **PKCE public client** does not — refresh works without a secret.

### JSON output for scripting

```sh
slack-pkce-auth --client-id $CID --output json | jq -r .access_token
```

```json
{
  "access_token": "xoxp-...",
  "refresh_token": "xoxe-...",
  "expires_at": 1735689600,
  "scope": "channels:read channels:history ...",
  "team_id": "T0123",
  "team_name": "Acme",
  "user_id": "U0123"
}
```

## Output formats

| `--output` | Use case |
|---|---|
| `token` (default) | `$(slack-pkce-auth ...)` for env var assignment |
| `json` | Pipe to `jq`, save to file, structured consumption |
| `env` | Redirect to `.env` for `--env-file` style consumers |
| `dotnet-secret` | Emits `dotnet user-secrets set` commands; pipe to `bash` |

## Custom listener port (`--port`)

By default the CLI listens on `localhost:8765` and the relay forwards the OAuth callback there. If you change `--port`, the relay has to forward to the new port — the CLI signals it by appending a `relay_port` query parameter to the redirect URL. The bundled `relay/callback.html` honors it (as does the default SlackDrive relay).

A direct `http://localhost` redirect URL uses no relay, so its own port is used as-is.

## How PKCE makes the relay safe

The redirect URL is a **public** GitHub Pages page. That sounds insecure, but PKCE makes it fine:

1. The CLI generates a `code_verifier` (random 64 bytes) locally
2. It sends only the SHA-256 hash (`code_challenge`) to Slack in the auth URL
3. Slack returns an authorization `code` to the relay page
4. The relay forwards `code` to the CLI's local listener (`localhost`, default `:8765`)
5. The CLI exchanges `code` + the original `code_verifier` for the token

Even if the relay page were compromised and stole the `code`, **without the `code_verifier` (which never leaves your machine) the code cannot be exchanged for a token**. The relay is trustless.

## Hosting your own relay

This repo ships a workflow (`.github/workflows/pages.yml`) that publishes the `relay/` folder to GitHub Pages, so the relay is served at:

```
https://yotsuda.github.io/slack-pkce-auth/callback.html
```

To host your own copy instead of depending on `yotsuda.github.io`:

1. Fork this repo
2. **Settings → Pages → Build and deployment → Source: GitHub Actions** — the bundled workflow deploys `relay/` on every push to `master`
3. Your relay URL becomes `https://<your-user>.github.io/slack-pkce-auth/callback.html`
4. Register that URL in your Slack App's **Redirect URLs**
5. Run with `--redirect-url https://<your-user>.github.io/slack-pkce-auth/callback.html`

`relay/callback.html` is a single static file with no dependencies (and it supports `--port` via `relay_port`).

## Default scopes

```
channels:read channels:history
groups:read groups:history
im:read im:history mpim:read mpim:history
users:read files:read chat:write
search:read search:read.public search:read.private
search:read.im search:read.mpim search:read.files search:read.users
```

Override with `--scopes "scope1 scope2 ..."`.

## Comparison

| | Browser tokens (`xoxc`/`xoxd`) | Manual `xoxp-` paste | `slack-pkce-auth` |
|---|---|---|---|
| Slack app creation | not needed | required | required |
| Scope configuration | n/a | manual paste in web UI | passed as a CLI flag |
| Token retrieval | harvest from DevTools | copy from web UI | printed to stdout |
| Token lifetime | short (session-bound) | long | long (+ optional refresh) |
| Client secret | n/a | n/a | only if app is confidential |
| Backend infrastructure | none | none | none |

## License

[MIT](LICENSE)
