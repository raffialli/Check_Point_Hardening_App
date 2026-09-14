# Check Point Hardening App - Open Public Edition

> Development line: Version 2.0 (`develop/v2`). The protected V1 baseline is tagged `v1.0.0-baseline`; V1 maintenance belongs on `release/v1`.

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

```sh
npm ci
npm start
```

Open `http://127.0.0.1:3000` in a browser. The backend listens on localhost by default.

To use another port:

```sh
PORT=8080 npm start
```

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
