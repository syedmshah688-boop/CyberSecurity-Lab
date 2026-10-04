# SOC Alert Triage Lab

A small, defensive Python project that reviews **synthetic** authentication events from a CSV file. It flags repeated failed logins from one IP and a successful login that follows repeated failures for the same account and IP.

## What it demonstrates
- Reading and validating structured security-event data
- Grouping failed logins by source IP and username
- Applying a configurable alert threshold
- Correlating a later successful login with earlier failures
- Communicating severity and findings in a concise console summary

## Requirements
- Python 3.9 or newer
- No third-party packages

## Run
From this folder:

```bash
python triage.py
```

Use a different CSV or threshold:

```bash
python triage.py data/auth_events.csv --threshold 4
```

The default threshold is 3. Expected sample findings include a medium alert for `203.0.113.10` and a high alert for account `amina` after repeated failures. The addresses in the dataset are reserved documentation examples, and all events are fictional.

## Input format
CSV columns: `timestamp` (`YYYY-MM-DD HH:MM:SS`), `username`, `source_ip`, and `event` (`failed_login` or `successful_login`). This is an educational triage exercise, not a production detection system. A real deployment needs log-source validation, time-zone handling, allowlists, tuning, retention controls, and human investigation before any response action.

## Project extension ideas
- Add Windows Event Log or Linux SSH log parsing
- Export alerts as JSON
- Add time-window-based detection
- Add unit tests and sample edge cases
- Create a small dashboard with alert counts

## LinkedIn project description
**SOC Alert Triage Lab | Python** — Built a lightweight defensive log-analysis tool that parses synthetic authentication events, identifies repeated login failures, and correlates successful logins after repeated failures. Added configurable thresholds, input validation, severity labels, and a concise analyst-facing summary. Python · CSV · Authentication Log Analysis · Alert Triage

