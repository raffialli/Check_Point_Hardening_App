# Check Point Hardening App - Open Public Edition

The Open Public Edition connects to a Check Point Security Management Server, Multi-Domain Server, or Smart-1 Cloud tenant, gathers Management API evidence, evaluates hardening checks, and can perform only the remediation actions explicitly offered in the interface.

This project is independent and is not created, endorsed, or supported by Check Point Software Technologies.

## Open Public Edition privacy model

- The app does not include a **Mark as Reviewed** control.
- The app does not keep an audit trail or per-check history of remediation changes.
- It does not retain a previous-scan summary across sessions.
- Credentials and scan results remain in process memory for the active session only.
- Credentials are sent from the browser to the local backend and then to the selected Check Point Management API endpoint. Passwords and API keys are not written to files by the app.
- PDF reports and debug logs are created only when the operator explicitly downloads them. Those downloads may contain environment details and must be handled as sensitive data.
- Normal runtime diagnostics are printed to the terminal to support troubleshooting; they are not stored by the app.

The repository intentionally excludes generated reports, screenshots, diagrams, packaged container images, dependency folders, caches, and machine-specific metadata.

## Requirements

- Node.js 20 or newer
- Network access from this computer to the target Check Point Management API
- A Check Point API account or API key with permissions appropriate for the checks and any requested remediation

## Run locally

Run these commands from the repository folder containing `package.json`. Initial dependency and browser installation requires internet access (or a prepared offline bundle).

### macOS / Linux

```sh
npm ci
npm run install:browsers
npm run check
npm start
```

Open `http://127.0.0.1:3000` in a browser. The backend listens on localhost by default.

To use another port:

```sh
PORT=8080 npm start
```

### Windows (PowerShell)

Install dependencies and the Chromium browser used for PDF export, then validate JavaScript syntax:

```powershell
npm ci
npm run install:browsers
npm run check
```

Configure the timeout values and start the app on port 3200:

```powershell
# Persist timeout settings for future sessions under your Windows user account.
[Environment]::SetEnvironmentVariable("CP_API_TIMEOUT_MS", "60000", "User")
[Environment]::SetEnvironmentVariable("CP_SIC_TEST_TIMEOUT_MS", "120000", "User")

# Apply settings to this PowerShell session as well.
$env:CP_API_TIMEOUT_MS = "60000"
$env:CP_SIC_TEST_TIMEOUT_MS = "120000"
$env:PORT = "3200"

npm start
```

Open [http://127.0.0.1:3200](http://127.0.0.1:3200). The app listens on localhost by default.

The timeout values are milliseconds: this setup allows 60 seconds for ordinary API requests and 120 seconds for SIC tests. The app defaults are 45 seconds and 120 seconds respectively; these overrides are configuration choices, not Windows requirements. Script task polling has a separate deadline described below.

The `User` settings persist, while `$env:` assignments apply to the current PowerShell process and the app launched from it. `PORT` is not persisted by these commands; set `$env:PORT = "3200"` again when starting from a new terminal. Restart the app after changing environment settings. `npm run check` checks syntax only; it does not test connectivity or credentials.

## Run for Prism

From the repository folder:

```sh
npm start
```

Open `http://127.0.0.1:3000` (port 3000 unless `PORT` is set). On the launch page, under the title, the app shows the `package.json` version and the short git SHA. If this checkout is behind `origin/main`, an update banner appears. Click **Update** to fast-forward, run `npm install` when `package.json` or the lockfile changed, and restart. The control is marked **localhost only**; hover that label for why a non-localhost page cannot run the update.

Live-pull risks:

- The process restarts. In-memory sessions, credentials, and scans are dropped. Log out before updating.
- `npm install` runs when dependency files changed, or when `node_modules` is missing, and needs network access. If it fails, the new commits stay checked out and the server is not restarted.
- A dirty working tree, a branch other than `main`, or history that is not a fast-forward is refused. The updater does not stash, reset, rebase, or force-update.
- The update check runs `git fetch` and moves the `origin/main` remote-tracking ref.
- If the process does not come back, start it again with `npm start`.

`APP_UPDATE_REMOTE` and `APP_UPDATE_BRANCH` default to `origin` and `main`. `APP_UPDATE_SOURCE` is the plug-in point for a later release check; only `git` is implemented, and one-click apply stays on that git path.

## Use

1. Select the management host type.
2. Enter the management host and authenticate with a password or API key.
3. For MDS, provide the domain and the MDS server hostname when Gaia checks are needed.
4. Run **Scan Hardening Posture**.
5. Review evidence and use remediation controls only after validating the target and impact.
6. Export a PDF only if a report is required, then log out and stop the process.

Remediation actions change the connected Check Point environment and require explicit confirmation in the browser. Test permissions and connectivity before using the app in production.

## Container use

Build and run with Docker:

```sh
docker build -f Docker/Dockerfile -t check-point-hardening-app:v2-dev .
docker run --rm --name check-point-hardening-v2 -p 127.0.0.1:3200:3100 check-point-hardening-app:v2-dev
```

Or use Compose:

```sh
docker compose -f Docker/compose.yaml up --build
```

Stop the app after the engagement:

```sh
docker compose -f Docker/compose.yaml down
```

To create a portable compressed image bundle for the default `linux/amd64` platform:

```sh
Docker/package_docker_image.sh
```

## Data handling checklist

- Do not commit exported reports or debug logs.
- Do not add customer names, hostnames, IP addresses, usernames, screenshots, or copied API responses to this repository.
- Keep engagement artifacts under `customer-data/`, `engagements/`, `reports/`, `exports/`, `screenshots/`, or `output/`; all are excluded from Git and Docker build contexts.
- Store any intentionally exported artifact in the approved engagement location.
- Stop the Node process or container after use to clear in-memory session data.
# Script task polling

Asynchronous `run-script` tasks are polled until every returned task completes.
`TASK_POLL_TIMEOUT_MS` defaults to `180000` (three minutes per script), independent
of polling intervals. Set it higher for slow Gaia collections if needed. This
replaces the former `TASK_POLL_ATTEMPTS` limit. Normal and Large Environment scans
share the deadline; their existing polling intervals and concurrency limits remain.
A poll request already in flight is still subject to the API request timeout.
Timeouts do not resubmit or cancel the remote script. Debug results include the
affected target and an explicit timeout message instead of only a lookup count.
