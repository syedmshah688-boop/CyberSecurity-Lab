#!/usr/bin/env python3
"""SOC Alert Triage Lab: summarize authentication events from a CSV file."""
import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def analyze(path: Path, threshold: int):
    events = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "username", "source_ip", "event"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("CSV must include timestamp, username, source_ip, event columns")
        for line, row in enumerate(reader, start=2):
            try:
                row["parsed_time"] = datetime.strptime(row["timestamp"], TIME_FORMAT)
            except ValueError as exc:
                raise ValueError(f"Invalid timestamp on CSV line {line}: {row['timestamp']}") from exc
            row["event"] = row["event"].strip().lower()
            if row["event"] not in {"failed_login", "successful_login"}:
                raise ValueError(f"Unsupported event on CSV line {line}: {row['event']}")
            events.append(row)

    failures_by_ip = Counter(row["source_ip"] for row in events if row["event"] == "failed_login")
    failures_by_user = Counter(row["username"] for row in events if row["event"] == "failed_login")
    alerts = []
    for ip, count in sorted(failures_by_ip.items()):
        if count >= threshold:
            alerts.append({"severity": "medium", "type": "repeated_failed_logins", "source_ip": ip,
                           "count": count, "summary": f"{count} failed logins from {ip}"})

    failed_times = defaultdict(list)
    for row in events:
        if row["event"] == "failed_login":
            failed_times[(row["source_ip"], row["username"])].append(row["parsed_time"])
    for row in events:
        if row["event"] != "successful_login":
            continue
        prior = [t for t in failed_times[(row["source_ip"], row["username"])] if t < row["parsed_time"]]
        if len(prior) >= threshold:
            alerts.append({"severity": "high", "type": "success_after_repeated_failures",
                           "source_ip": row["source_ip"], "username": row["username"],
                           "count": len(prior), "summary": f"Successful login for {row['username']} from {row['source_ip']} after {len(prior)} earlier failures"})

    alerts.sort(key=lambda alert: (alert["severity"] != "high", alert["source_ip"], alert["type"]))
    summary = {
        "events_reviewed": len(events),
        "failed_logins": sum(failures_by_ip.values()),
        "successful_logins": sum(row["event"] == "successful_login" for row in events),
        "unique_source_ips": len({row["source_ip"] for row in events}),
        "failed_logins_by_ip": dict(failures_by_ip.most_common()),
        "failed_logins_by_username": dict(failures_by_user.most_common()),
        "alerts": alerts,
    }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Triage a CSV of authentication events.")
    parser.add_argument("csv_file", nargs="?", default="data/auth_events.csv", help="Path to the input CSV")
    parser.add_argument("--threshold", type=int, default=3, help="Failures needed to raise an alert (default: 3)")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    try:
        result = analyze(Path(args.csv_file), args.threshold)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Events reviewed: {result['events_reviewed']}")
    print(f"Failed logins: {result['failed_logins']} | Successful logins: {result['successful_logins']}")
    print("\nAlerts:")
    if not result["alerts"]:
        print("  No alerts at the configured threshold.")
    for alert in result["alerts"]:
        print(f"  [{alert['severity'].upper()}] {alert['summary']}")
    print("\nFailed logins by source IP:")
    for ip, count in result["failed_logins_by_ip"].items():
        print(f"  {ip}: {count}")


if __name__ == "__main__":
    main()

