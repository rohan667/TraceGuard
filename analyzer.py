"""Small, explainable detection rules for the TraceGuard demo."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime


REQUIRED_FIELDS = ("timestamp", "host", "event_type")


def normalize_events(events):
    if not isinstance(events, list):
        raise ValueError("Events must be a JSON array.")
    if len(events) > 5000:
        raise ValueError("A maximum of 5,000 events is supported per upload.")
    normalized = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event {index + 1} must be a JSON object.")
        missing = [field for field in REQUIRED_FIELDS if not event.get(field)]
        if missing:
            raise ValueError(f"Event {index + 1} is missing required field(s): {', '.join(missing)}.")
        try:
            datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Event {index + 1} has an invalid ISO timestamp.") from exc
        item = {
            "id": str(event.get("id", f"upload-{index + 1}"))[:80],
            "timestamp": str(event["timestamp"])[:40],
            "host": str(event["host"])[:120],
            "source": str(event.get("source", "unknown"))[:80],
            "event_type": str(event["event_type"]).lower()[:80],
            "username": str(event.get("username", "unknown"))[:120],
            "src_ip": str(event.get("src_ip", "unknown"))[:80],
            "command_line": str(event.get("command_line", ""))[:1000],
            "target": str(event.get("target", ""))[:160],
        }
        normalized.append(item)
    return normalized


def alert(rule_id, title, severity, description, event_ids, technique_id, technique_name, recommendation):
    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "event_ids": event_ids,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "recommendation": recommendation,
    }


def analyze_events(events):
    """Return deterministic alerts; rules intentionally favor explainability."""
    events = normalize_events(events)
    alerts = []
    failed_groups = defaultdict(list)

    for event in events:
        kind = event["event_type"]
        if kind in ("login_failed", "authentication_failure"):
            failed_groups[(event["username"], event["src_ip"])].append(event)

        command = event["command_line"].lower()
        if kind in ("process_created", "process_start") and "powershell" in command and any(
            marker in command for marker in ("-enc", "-encodedcommand", "frombase64string")
        ):
            alerts.append(alert(
                "TG-PS-001", "Encoded PowerShell command", "high",
                f"An encoded PowerShell command ran on {event['host']} under {event['username']}. Encoded commands can hide their intent.",
                [event["id"]], "T1059.001", "PowerShell",
                "Review the decoded command and parent process. Confirm whether the activity was approved, then isolate the host if it is unexplained.",
            ))

        if kind in ("user_added_to_admins", "privileged_group_change"):
            alerts.append(alert(
                "TG-IAM-001", "Privileged group membership changed", "critical",
                f"{event['username']} was associated with a privileged group change on {event['host']}.",
                [event["id"]], "T1098", "Account Manipulation",
                "Verify the change against an approved request. If unauthorized, remove the membership and review nearby account activity.",
            ))

        if kind == "login_success":
            earlier_failures = [f for f in failed_groups.get((event["username"], event["src_ip"]), [])
                                if f["timestamp"] <= event["timestamp"]]
            if len(earlier_failures) >= 5:
                alerts.append(alert(
                    "TG-AUTH-002", "Successful login after repeated failures", "high",
                    f"A successful login for {event['username']} from {event['src_ip']} followed {len(earlier_failures)} failed attempts in the supplied events.",
                    [f["id"] for f in earlier_failures] + [event["id"]], "T1110", "Brute Force",
                    "Confirm the user recognizes the login, check MFA and session activity, and reset credentials if compromise is suspected.",
                ))

    for (username, source_ip), group in failed_groups.items():
        if len(group) >= 5:
            alerts.append(alert(
                "TG-AUTH-001", "Repeated authentication failures", "high",
                f"{len(group)} failed login attempts for {username} came from {source_ip} in the supplied events.",
                [item["id"] for item in group], "T1110", "Brute Force",
                "Check whether the source is expected, review successful logins for the same account, and apply account protections if needed.",
            ))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(alerts, key=lambda item: (severity_order[item["severity"]], item["title"], item["id"]))
