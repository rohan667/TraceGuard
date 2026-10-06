# TraceGuard — Detection Workbench

TraceGuard is a small, local security log analysis demo. It turns a JSON array of synthetic or user-supplied events into explainable alerts, maps detections to MITRE ATT&CK, and offers analyst next steps. It uses Python's standard library, so there are no packages to install.

> **Safe-use note:** the included records and scenarios are synthetic. TraceGuard is an educational prototype, not a production SIEM or incident-response tool. Analyze only logs you are authorized to use. The app binds to `127.0.0.1` and is intended to run on your own computer.

## What it demonstrates

- Rule-based detection for repeated login failures, a successful login after repeated failures, encoded PowerShell, and privileged group changes.
- Severity, evidence event IDs, plain-language rationale, ATT&CK technique references, and suggested analyst review steps.
- Three safe, one-click scenarios, searchable event stream, JSON upload, and downloadable JSON incident report.
- A small HTTP API and input validation, with no external service or dependency.

## Requirements

- Python 3.9 or newer.
- Visual Studio Code (recommended) or another code editor.
- Git and a GitHub account only if you want to publish the project.

## Run it

1. Download and unzip the project, or clone your GitHub repository.
2. Open the **traceguard** folder in VS Code using **File → Open Folder**.
3. Open the integrated terminal with **Terminal → New Terminal**.
4. Confirm Python is installed with `python3 --version` (on Windows, try `py --version`).
5. Start the app from the project folder:

   **macOS / Linux**
   ```bash
   python3 app.py
   ```

   **Windows**
   ```powershell
   py app.py
   ```

6. Open <http://127.0.0.1:8000> in your browser. Keep the terminal open while using it. Stop the server with **Ctrl+C**.

If port 8000 is already in use, change `PORT = 8000` in `app.py` to `PORT = 8001`, restart, and open `http://127.0.0.1:8001`.

## Try the project

1. Review the initial dashboard and its four rule matches.
2. Click each **Run scenario** card and observe the alert, evidence, and ATT&CK mapping.
3. Click **Reset demo** to restore the sample dataset.
4. Choose **Analyze a JSON file** to upload a JSON array in the format below.
5. Search the event stream or export the current results as a JSON report.

## Event format

Required fields are `timestamp`, `host`, and `event_type`. Timestamps should be ISO 8601. Other fields are optional.

```json
[
  {
    "id": "event-001",
    "timestamp": "2026-10-06T12:00:00Z",
    "host": "demo-workstation",
    "source": "Windows Security",
    "event_type": "login_failed",
    "username": "demo.user",
    "src_ip": "203.0.113.10",
    "command_line": "",
    "target": ""
  }
]
```

Supported event names for the built-in rules:

| Event type | Detection behavior |
| --- | --- |
| `login_failed` or `authentication_failure` | Five or more failures for the same username and source IP produce an alert. |
| `login_success` | A success following five or more failures for the same username and source IP produces an alert. |
| `process_created` or `process_start` | PowerShell command lines containing `-enc`, `-encodedcommand`, or `frombase64string` produce an alert. |
| `user_added_to_admins` or `privileged_group_change` | A privileged group change produces an alert. |

For real log formats, normalize the fields into this schema first. This prototype does not decode or execute commands.

## Project files

```text
traceguard/
├── app.py                 # Local HTTP server and API
├── analyzer.py            # Validated, explainable detection rules
├── app.js                 # Dashboard behavior
├── index.html             # Dashboard page
├── styles.css             # Dashboard styling
├── data/
│   ├── sample_events.json # Synthetic starting data
│   └── scenarios.json     # One-click synthetic scenarios
├── .gitignore
├── README.md
└── CODING_PROMPT.md       # Prompt to extend the project with an AI coding tool
```

## API endpoints

- `GET /api/health` — local server health.
- `GET /api/events` — sample events and their alerts.
- `GET /api/scenarios` — available scenarios.
- `POST /api/scenario` — body: `{"id":"password-spray"}` (or another scenario ID).
- `POST /api/analyze` — body: an event array in the schema above.

## Publish to GitHub

Create a **public** empty repository on GitHub named `traceguard` (do not add a README, license, or `.gitignore`, because this folder already has files). In VS Code, open the terminal in this folder and run:

```bash
git init
git add .
git commit -m "Build TraceGuard detection workbench"
git branch -M main
git remote add origin https://github.com/YOUR-GITHUB-USERNAME/traceguard.git
git push -u origin main
```

Replace `YOUR-GITHUB-USERNAME` with your GitHub username. GitHub may open a browser sign-in prompt. If `git remote add origin` says a remote already exists, use `git remote set-url origin https://github.com/YOUR-GITHUB-USERNAME/traceguard.git` and continue. Do not commit real security logs, secrets, passwords, or personal information.

## Portfolio presentation

In a short screen recording, show the dashboard, run the repeated-login and privileged-change scenarios, open the alert evidence and ATT&CK mapping, then upload the sample file and export a report. Explain one detection rule and one limitation: this demo uses simple thresholds and normalized sample events, so an analyst must validate every alert. That demonstrates judgment as well as coding.

## Extension ideas

- Add a rule configuration file and a small rule test suite.
- Add time-windowed thresholds and reduce duplicate alerts.
- Normalize a documented, public sample log format.
- Add tests and a GitHub Actions workflow for linting and test execution.
- Add a threat-model document covering input validation, local-only binding, and privacy.
