
import csv
import os
import tempfile
from datetime import datetime, timezone, timedelta

import adaptive_policy as policy

namespace = "image-pull-mitigation-lab"
now = datetime.now(timezone.utc)

def make_event(seconds_ago, event_type, severity="NORMAL"):
    return {
        "timestamp": (now - timedelta(seconds=seconds_ago)).isoformat(),
        "namespace": namespace,
        "event_type": event_type,
        "severity": severity,
    }

tests = [
    ("NORMAL", []),
    ("SUSPICIOUS", [
        make_event(5, "POD_CREATED"),
        make_event(4, "POD_CREATED"),
        make_event(3, "POD_CREATED"),
        make_event(2, "POD_CREATED"),
        make_event(1, "POD_CREATED"),
    ]),
    ("PULL_FLOOD", [
        make_event(10 - i, "POD_CREATED")
        for i in range(10)
    ]),
]

original_file = policy.CSV_FILE
original_state = policy.current_state

try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        newline="",
        encoding="utf-8",
        suffix=".csv",
        delete=False,
    ) as file:
        temp_file = file.name
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp", "namespace", "event_type", "severity"
            ],
        )
        writer.writeheader()

    policy.CSV_FILE = temp_file

    for expected, events in tests:
        with open(temp_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "timestamp", "namespace", "event_type", "severity"
                ],
            )
            writer.writeheader()
            writer.writerows(events)

        policy.current_state = "NORMAL"
        policy.recovery_started = None

        rows = policy.read_events()
        actual, count = policy.select_policy(rows, now)

        result = "PASS" if actual == expected else "FAIL"
        print(
            f"{result}: expected={expected}, actual={actual}, "
            f"churn_60s={count}"
        )

finally:
    policy.CSV_FILE = original_file
    policy.current_state = original_state
    policy.recovery_started = None
    if "temp_file" in locals() and os.path.exists(temp_file):
        os.remove(temp_file)
