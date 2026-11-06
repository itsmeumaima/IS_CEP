
import csv
import os
import re
import subprocess
import time

from datetime import datetime, timezone


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_FILE = os.path.join(
    BASE_DIR,
    "detector_events.csv"
)

NAMESPACE = os.getenv(
    "MITIGATOR_NAMESPACE",
    "image-pull-mitigation-lab"
)

CPU_HIGH = 80
MEMORY_HIGH = 80

CPU_LOW = 70
MEMORY_LOW = 70

REQUIRED_HIGH_READINGS = 3
REQUIRED_LOW_READINGS = 3

POLL_INTERVAL = 10
PRESSURE_REFRESH_SECONDS = 30


# --------------------------------------------------
# MONITOR STATE
# --------------------------------------------------

pressure_active = False

high_readings = 0
low_readings = 0

last_pressure_event = 0


# --------------------------------------------------
# METRIC PARSING
# --------------------------------------------------

def get_percentage(value):

    match = re.search(r"(\d+(?:\.\d+)?)%", str(value))

    if not match:
        return None

    return float(match.group(1))


# --------------------------------------------------
# GET KUBERNETES NODE METRICS
# --------------------------------------------------

def get_node_metrics():

    result = subprocess.run(
        [
            "kubectl",
            "top",
            "nodes",
            "--no-headers"
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=20
    )

    metrics = []

    for line in result.stdout.strip().splitlines():

        parts = line.split()

        if len(parts) < 5:
            continue

        cpu = get_percentage(parts[2])
        memory = get_percentage(parts[4])

        if cpu is None or memory is None:
            print(
                f"Skipping invalid metrics: {line}",
                flush=True
            )
            continue

        metrics.append({
            "node": parts[0],
            "cpu": cpu,
            "memory": memory
        })

    return metrics


# --------------------------------------------------
# WRITE RESOURCE EVENTS TO CSV
# --------------------------------------------------


def write_event(event_type, details):

    fieldnames = [
        "timestamp",
        "namespace",
        "pod",
        "event_type",
        "reason",
        "churn_60s",
        "severity",
        "details",
        "pod_uid",
        "container",
        "image",
        "image_source",
        "failure_count",
        "dedupe_key",
    ]

    file_exists = os.path.exists(CSV_FILE)
    needs_header = not file_exists or os.path.getsize(CSV_FILE) == 0

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "namespace": NAMESPACE,
        "pod": "NODE",
        "event_type": event_type,
        "reason": "Resource monitoring",
        "churn_60s": 0,
        "severity": (
            "HIGH" if event_type == "RESOURCE_PRESSURE" else "INFO"
        ),
        "details": str(details).replace("\n", " ").replace("\r", " "),
        "pod_uid": "",
        "container": "",
        "image": "",
        "image_source": "",
        "failure_count": "",
        "dedupe_key": "",
    }

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if needs_header:
            writer.writeheader()

        writer.writerow(record)
        file.flush()


# --------------------------------------------------
# RESOURCE PRESSURE CONDITIONS
# --------------------------------------------------

def is_resource_high(node):

    return (
        node["cpu"] >= CPU_HIGH
        or node["memory"] >= MEMORY_HIGH
    )


def is_resource_low(node):

    return (
        node["cpu"] < CPU_LOW
        and node["memory"] < MEMORY_LOW
    )


# --------------------------------------------------
# MAIN MONITOR
# --------------------------------------------------

def main():

    global pressure_active
    global high_readings
    global low_readings
    global last_pressure_event

    print("\nResource Pressure Monitor Started")
    print("-----------------------------------")

    print(f"Namespace: {NAMESPACE}")
    print(f"CSV file: {CSV_FILE}")

    print(f"CPU high threshold: {CPU_HIGH}%")
    print(f"Memory high threshold: {MEMORY_HIGH}%")

    print(f"CPU recovery threshold: below {CPU_LOW}%")
    print(f"Memory recovery threshold: below {MEMORY_LOW}%")

    print(
        f"Required high readings: {REQUIRED_HIGH_READINGS}"
    )

    print(
        f"Required low readings: {REQUIRED_LOW_READINGS}"
    )

    print(f"Polling interval: {POLL_INTERVAL}s")

    print(
        f"Pressure refresh interval: "
        f"{PRESSURE_REFRESH_SECONDS}s"
    )

    print(
        "\nMonitoring only. "
        "No Kubernetes resources will be changed.\n"
    )

    try:

        while True:

            try:

                nodes = get_node_metrics()

                if not nodes:

                    print(
                        "No valid node metrics available.",
                        flush=True
                    )

                    time.sleep(POLL_INTERVAL)
                    continue

                # Evaluate the worst node in this polling cycle.
                # This avoids counting several nodes as several
                # consecutive readings in one cycle.

                worst_node = max(
                    nodes,
                    key=lambda node: max(
                        node["cpu"],
                        node["memory"]
                    )
                )

                cpu = worst_node["cpu"]
                memory = worst_node["memory"]

                print(
                    f"Node: {worst_node['node']} | "
                    f"CPU: {cpu:g}% | "
                    f"Memory: {memory:g}%",
                    flush=True
                )

                high = any(
                    is_resource_high(node)
                    for node in nodes
                )

                low = all(
                    is_resource_low(node)
                    for node in nodes
                )

                # ------------------------------------------
                # PRESSURE DETECTION
                # ------------------------------------------

                if not pressure_active:

                    if high:

                        high_readings += 1

                        print(
                            f"High readings: "
                            f"{high_readings}/"
                            f"{REQUIRED_HIGH_READINGS}",
                            flush=True
                        )

                    else:

                        high_readings = 0

                    if high_readings >= REQUIRED_HIGH_READINGS:

                        pressure_active = True

                        low_readings = 0

                        details = (
                            f"Node={worst_node['node']}, "
                            f"CPU={cpu:g}%, "
                            f"Memory={memory:g}%, "
                            f"High readings={high_readings}"
                        )

                        write_event(
                            "RESOURCE_PRESSURE",
                            details
                        )

                        last_pressure_event = time.monotonic()

                        print(
                            "\nRESOURCE PRESSURE DETECTED\n",
                            flush=True
                        )

                # ------------------------------------------
                # PRESSURE MONITORING AND RECOVERY
                # ------------------------------------------

                else:

                    if low:

                        low_readings += 1

                        print(
                            f"Recovery readings: "
                            f"{low_readings}/"
                            f"{REQUIRED_LOW_READINGS}",
                            flush=True
                        )

                    else:

                        low_readings = 0

                    # --------------------------------------
                    # PRESSURE CLEARED
                    # --------------------------------------

                    if low_readings >= REQUIRED_LOW_READINGS:

                        details = (
                            f"All monitored nodes below recovery "
                            f"thresholds. "
                            f"CPU={cpu:g}%, "
                            f"Memory={memory:g}%"
                        )

                        write_event(
                            "RESOURCE_PRESSURE_CLEARED",
                            details
                        )

                        pressure_active = False

                        high_readings = 0
                        low_readings = 0

                        last_pressure_event = 0

                        print(
                            "\nRESOURCE PRESSURE CLEARED\n",
                            flush=True
                        )

                    # --------------------------------------
                    # REFRESH ACTIVE PRESSURE EVENT
                    # --------------------------------------

                    elif (
                        time.monotonic() - last_pressure_event
                        >= PRESSURE_REFRESH_SECONDS
                    ):

                        details = (
                            f"Pressure remains active. "
                            f"Node={worst_node['node']}, "
                            f"CPU={cpu:g}%, "
                            f"Memory={memory:g}%"
                        )

                        write_event(
                            "RESOURCE_PRESSURE",
                            details
                        )

                        last_pressure_event = time.monotonic()

                        print(
                            "RESOURCE PRESSURE EVENT REFRESHED",
                            flush=True
                        )

            except subprocess.CalledProcessError as error:

                print(
                    "Could not retrieve Kubernetes metrics: "
                    f"{error.stderr or error}",
                    flush=True
                )

            except subprocess.TimeoutExpired:

                print(
                    "Kubernetes metrics request timed out.",
                    flush=True
                )

            except Exception as error:

                print(
                    f"Monitoring error: {error}",
                    flush=True
                )

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:

        print(
            "\nResource pressure monitor stopped.",
            flush=True
        )


if __name__ == "__main__":
    main()
