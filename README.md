# Telegram Changes Checker

A Telegram resource and MTProto change monitor based on the original checker by the project author.

The customized version keeps the original detection mechanisms while adapting the project for our workflow:

- English-only code, logs, notifications, and documentation.
- One common Git repository for production, test, and language-pack data.
- GitHub Actions for scheduled execution instead of a permanent VPS process.
- Production and test detection, with all notifications sent only through the production bot to one configurable production channel.
- Gemini-powered English change summaries.
- Readable test-server variant directories.

## Monitoring

### HTTP resources

`prod.txt` contains production resources.

`test.txt` contains test resources. Test URLs are checked against the five real Telegram hostname variants used by the original checker:

- `b-`
- `i-`
- `l-`
- `a-`
- `y-`

The prefixes remain unchanged for network requests. They are stored in the data repository using readable directory names such as `variant-b`.

### Telegram MTProto methods

The checker calls the configured Telegram raw API methods, sanitizes sensitive/volatile fields, normalizes known dynamic values, and stores comparable JSON snapshots.

### Language packs

Language packs are tracked with Telegram's langpack API. Existing versions use `getDifference` so only changes need to be processed after the initial snapshot.

## Data repository

All generated data is stored in one repository:

```
data-repository/
├── production/
├── test/
│   ├── variant-b/
│   ├── variant-i/
│   ├── variant-l/
│   ├── variant-a/
│   └── variant-y/
└── langpacks/
```

The exact files below these directories are produced by the existing checker logic.

## Configuration

The checker reads secrets from environment variables or the local `local_secrets.py` fallback.

| Variable | Purpose |
|---|---|
| `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` | Telegram MTProto application credentials |
| `GEMINI_API_KEY` | Gemini API access for change summaries |
| `TG_BOT_TOKEN_PROD` | Production notification bot |
| `TG_NOTIFICATION_CHANNEL` | Production Telegram channel for all notifications (defaults to `@botapinews`) |
| `DATA_REPOSITORY_TOKEN` | Token with access to the common data repository |
| `TELEGRAM_SESSION_PROD` / `TELEGRAM_SESSION_TEST` | Compact Pyrogram session strings for GitHub Actions |
| `DATA_REPOSITORY_URL` | Common generated-data repository |
| `DATA_REPOSITORY_BRANCH` | Branch used for generated data |
| `DATA_REPOSITORY_DIR` | Local checkout directory |
| `RESOURCE_WATCHER_ENVIRONMENTS` | Environments to detect, normally `prod,test` |
| `RESOURCE_WATCHER_RUN_ONCE` | Run one complete cycle and exit |

See `.env.example` for the configuration template.

## Local development

Install the required Python dependencies, configure the secrets, clone the common data repository into the configured data directory, and run:

```bash
python3 main.py
```

For a single checking cycle:

```bash
RESOURCE_WATCHER_RUN_ONCE=1 python3 main.py
```

Telegram sessions can be authorized with:

```bash
python3 authorize.py --env both
```

## GitHub Actions

The target deployment uses a scheduled GitHub Actions workflow. The checker runs once per invocation, checks both production and the Telegram Test Server, updates the common data repository, sends every notification through the production bot to the configured production channel, and exits. A test-server bot token is not required.

GitHub's current scheduled-workflow minimum interval is five minutes. Scheduled runs can still be delayed during periods of high Actions load, so the workflow is designed to be safe when a run starts later than the nominal schedule. Scheduled workflows run from the repository default branch, so the `custom` branch will become the deployment/default branch only after our version is ready; `main` remains the untouched original branch.

## Design principle

This project intentionally avoids unnecessary rewrites. Existing detection, normalization, state tracking, retry handling, separate notification flows, and MTProto/LangPack behavior are preserved unless a change is required for the new deployment model.
