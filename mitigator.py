import argparse
import csv
import os
import time

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

NAMESPACE = os.getenv(
    "MITIGATOR_NAMESPACE",
    "image-pull-mitigation-lab"
)
QUOTA_NAME = "adaptive-pod-limit"
QUOTA_PODS = "3"
CSV_FILE = "detector_events.csv"


def apply_quota():
    core = client.CoreV1Api()
    body = client.V1ResourceQuota(
        metadata=client.V1ObjectMeta(
            name=QUOTA_NAME,
            labels={"app": "image-pull-defense"}
        ),
        spec=client.V1ResourceQuotaSpec(
            hard={"pods": QUOTA_PODS}
        )
    )

    try:
        core.create_namespaced_resource_quota(
            namespace=NAMESPACE, body=body
        )
        print(f"MITIGATION APPLIED: Pod quota set to {QUOTA_PODS}")
    except ApiException as exc:
        if exc.status == 409:
            core.patch_namespaced_resource_quota(
                name=QUOTA_NAME,
                namespace=NAMESPACE,
                body={"spec": {"hard": {"pods": QUOTA_PODS}}}
            )
            print(f"MITIGATION UPDATED: Pod quota set to {QUOTA_PODS}")
        else:
            raise


def read_rows():
    if not os.path.exists(CSV_FILE):
        return []

    with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply a Kubernetes Pod quota when HIGH severity is detected"
    )
    args = parser.parse_args()

    if args.apply:
        config.load_kube_config()

    existing_rows = read_rows()
    processed_rows = len(existing_rows)

    print(f"Watching {os.path.abspath(CSV_FILE)}")
    print(f"Target namespace: {NAMESPACE}")
    print(f"Apply mode: {args.apply}")
    print(f"Ignoring {processed_rows} existing records.")
    print("Waiting for NEW HIGH severity events. Press Ctrl+C to stop.")

    mitigation_applied = False

    try:
        while True:
            rows = read_rows()

            # Handle a log file that was cleared or recreated.
            if len(rows) < processed_rows:
                processed_rows = 0

            new_rows = rows[processed_rows:]
            processed_rows = len(rows)

            for row in new_rows:
                event_namespace = row.get("namespace", "").strip()

                if event_namespace != NAMESPACE:
                    continue

                severity = row.get("severity", "").strip().upper()

                if severity == "HIGH":
                    timestamp = row.get("timestamp", "-")
                    pod = row.get("pod", "-")
                    event_type = row.get("event_type", "-")
                    churn = row.get("churn_60s", "-")

                    print(
                        f"\nHIGH EVENT DETECTED: {timestamp} | "
                        f"pod={pod} | event={event_type} | "
                        f"churn_60s={churn}",
                        flush=True
                    )

                    if args.apply and not mitigation_applied:
                        apply_quota()
                        mitigation_applied = True
                    elif not args.apply:
                        print(
                            "DRY RUN: detection received; "
                            "no cluster changes made.",
                            flush=True
                        )

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nMitigator stopped.")


if __name__ == "__main__":
    main()
