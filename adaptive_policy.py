import csv
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

# ==================================================
# CONFIGURATION
# All values can be overridden with environment vars.
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.getenv("DETECTOR_CSV_FILE", os.path.join(BASE_DIR, "detector_events.csv"))
STATE_FILE = os.getenv(
    "ADAPTIVE_STATE_FILE",
    os.getenv(
        "POLICY_STATE_FILE",
        os.path.join(BASE_DIR, "adaptive_state.txt"),
    ),
)

NAMESPACE = os.getenv("POLICY_NAMESPACE", "image-pull-mitigation-lab")


def env_int(name, default, minimum=1):
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        print(f"Invalid {name}; using default {default}.", flush=True)
        return default


def env_float(name, default, minimum=0.0):
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        print(f"Invalid {name}; using default {default}.", flush=True)
        return default


WINDOW_SECONDS = env_int("POLICY_WINDOW_SECONDS", 120)
SUSPICIOUS_CHURN = env_int("POLICY_SUSPICIOUS_CHURN", 5)
HIGH_CHURN = env_int("POLICY_HIGH_CHURN", 10)
SUSPICIOUS_RATE = env_float("POLICY_SUSPICIOUS_RATE", 0.05)
HIGH_RATE = env_float("POLICY_HIGH_RATE", 0.10)

# Historical baseline: the period immediately before the active window.
BASELINE_SECONDS = env_int("POLICY_BASELINE_SECONDS", 600)
BASELINE_MULTIPLIER = env_float("POLICY_BASELINE_MULTIPLIER", 3.0, minimum=1.0)
BASELINE_RATE_FLOOR = env_float("POLICY_BASELINE_RATE_FLOOR", 0.025)
BEHAVIOR_MIN_CHURN = env_int("POLICY_BEHAVIOR_MIN_CHURN", 3)

# Image-pull failure thresholds.
PULL_FLOOD_UNIQUE_PODS = env_int("POLICY_PULL_FLOOD_UNIQUE_PODS", 3)
PULL_FLOOD_REPEATED_FAILURES = env_int("POLICY_PULL_FLOOD_REPEATED_FAILURES", 5)
LONG_FAILURE_SPAN_SECONDS = env_int("POLICY_LONG_FAILURE_SPAN_SECONDS", 60)

RECOVERY_AFTER_SECONDS = env_int("POLICY_RECOVERY_QUIET_SECONDS", 120)
RECOVERY_STABLE_SECONDS = env_int("POLICY_RECOVERY_STABLE_SECONDS", 30)
POLL_SECONDS = env_float("POLICY_POLL_SECONDS", 2.0, minimum=0.1)
LOG_INTERVAL = env_int("POLICY_LOG_INTERVAL", 15)

CHURN_EVENTS = {"POD_CREATED", "POD_DELETED"}
IMAGE_PULL_FAILURE_EVENTS = {
    "IMAGE_PULL_FAILURE",
    "POD_IMAGE_PULL_FAILURE",
}
RESOURCE_EVENTS = {"RESOURCE_PRESSURE", "RESOURCE_PRESSURE_CLEARED"}
THREAT_EVENTS = CHURN_EVENTS | IMAGE_PULL_FAILURE_EVENTS | {"ORPHAN_PULL_CONFIRMED"}

VALID_STATES = {
    "NORMAL",
    "SUSPICIOUS",
    "ORPHAN_PULL",
    "PULL_FLOOD",
    "RESOURCE_PRESSURE",
    "RECOVERY",
}

# ==================================================
# POLICY STATE
# ==================================================

current_state = "NORMAL"
recovery_started = None  # monotonic time at which the stability check began
last_status_log = 0.0


# ==================================================
# TIMESTAMP AND STATE HELPERS
# ==================================================

def parse_timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None


def load_state():
    if not os.path.exists(STATE_FILE):
        return "NORMAL"
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as file:
            saved_state = file.read().strip().upper()
        return saved_state if saved_state in VALID_STATES else "NORMAL"
    except OSError as exc:
        print(f"Unable to read saved state: {exc}", flush=True)
        return "NORMAL"


def save_state(state):
    temporary_file = STATE_FILE + ".tmp"
    try:
        with open(temporary_file, "w", encoding="utf-8") as file:
            file.write(state)
        os.replace(temporary_file, STATE_FILE)
    except OSError as exc:
        print(f"Unable to save policy state: {exc}", flush=True)


# ==================================================
# CSV EVENT READING
# Existing detector schema:
# timestamp,namespace,pod,event_type,reason,churn_60s,severity,details
# ==================================================

def read_events():
    if not os.path.exists(CSV_FILE):
        return []
    try:
        with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)
            return [
                row for row in reader
                if (row.get("namespace") or "").strip() == NAMESPACE
            ]
    except (OSError, csv.Error) as exc:
        print(f"Unable to read detector log: {exc}", flush=True)
        return []


def collect_events(rows, now):
    """Parse rows once and discard malformed or future-dated events."""
    parsed = []
    for row in rows:
        event_time = parse_timestamp(row.get("timestamp", ""))
        if event_time is None or event_time > now:
            continue
        event_type = (row.get("event_type") or "").strip().upper()
        parsed.append((event_time, row, event_type))
    parsed.sort(key=lambda item: item[0])
    return parsed


# ==================================================
# METRICS
# ==================================================

def calculate_metrics(events, now):
    window_start = now - timedelta(seconds=WINDOW_SECONDS)
    baseline_end = window_start
    baseline_start = baseline_end - timedelta(seconds=BASELINE_SECONDS)

    recent = [item for item in events if window_start <= item[0] <= now]
    baseline = [
        item for item in events
        if baseline_start <= item[0] < baseline_end
        and (item[1].get("severity") or "").strip().upper() != "HIGH"
    ]

    churn_recent = [item for item in recent if item[2] in CHURN_EVENTS]
    churn_baseline = [item for item in baseline if item[2] in CHURN_EVENTS]

    churn_count = len(churn_recent)
    churn_rate = churn_count / float(WINDOW_SECONDS)
    baseline_rate = len(churn_baseline) / float(BASELINE_SECONDS)

    behavior_anomaly = (
        churn_count >= BEHAVIOR_MIN_CHURN
        and churn_rate >= max(BASELINE_RATE_FLOOR, baseline_rate * BASELINE_MULTIPLIER)
    )

    pull_failures = [item for item in recent if item[2] in IMAGE_PULL_FAILURE_EVENTS]
    failures_by_pod = defaultdict(list)
    for event_time, row, _ in pull_failures:
        pod = (row.get("pod") or "").strip()
        if pod:
            failures_by_pod[pod].append(event_time)

    unique_failed_pods = len(failures_by_pod)
    repeated_failures = sum(max(0, len(times) - 1) for times in failures_by_pod.values())

    # This is the span between observed failure records for each Pod, not
    # guaranteed continuous failure duration (the detector does not emit
    # explicit pull-start/pull-recovered timestamps).
    failure_spans = {
        pod: (max(times) - min(times)).total_seconds()
        for pod, times in failures_by_pod.items()
    }
    longest_observed_failure_span = max(failure_spans.values(), default=0.0)
    long_failure_pods = sum(
        span >= LONG_FAILURE_SPAN_SECONDS for span in failure_spans.values()
    )

    recent_types = {item[2] for item in recent}
    resource_events = [item for item in events if item[2] in RESOURCE_EVENTS]
    latest_resource_event = resource_events[-1][2] if resource_events else None

    threat_activity = [item[0] for item in events if item[2] in THREAT_EVENTS]
    # Resource pressure and its clearance also restart the recovery quiet clock.
    resource_activity = [item[0] for item in events if item[2] in RESOURCE_EVENTS]
    all_recovery_activity = threat_activity + resource_activity
    last_activity = max(all_recovery_activity, default=None)
    quiet_seconds = (
        (now - last_activity).total_seconds()
        if last_activity is not None else float("inf")
    )

    return {
        "recent": recent,
        "recent_types": recent_types,
        "churn_count": churn_count,
        "churn_rate": churn_rate,
        "baseline_churn_count": len(churn_baseline),
        "baseline_rate": baseline_rate,
        "behavior_anomaly": behavior_anomaly,
        "pull_failure_count": len(pull_failures),
        "unique_failed_pods": unique_failed_pods,
        "repeated_failures": repeated_failures,
        "longest_observed_failure_span": longest_observed_failure_span,
        "long_failure_pods": long_failure_pods,
        "latest_resource_event": latest_resource_event,
        "quiet_seconds": quiet_seconds,
    }


def metrics_text(m):
    return (
        f"churn_{WINDOW_SECONDS}s={m['churn_count']} | "
        f"churn_rate={m['churn_rate']:.3f}/s | "
        f"baseline_rate={m['baseline_rate']:.3f}/s "
        f"(baseline_events={m['baseline_churn_count']}) | "
        f"behavior_anomaly={m['behavior_anomaly']} | "
        f"pull_failures={m['pull_failure_count']} | "
        f"unique_failed_pods={m['unique_failed_pods']} | "
        f"repeated_failures={m['repeated_failures']} | "
        f"longest_observed_failure_span={m['longest_observed_failure_span']:.1f}s"
    )


# ==================================================
# POLICY EVALUATION
# ==================================================

def select_policy(rows, now):
    global recovery_started

    events = collect_events(rows, now)
    m = calculate_metrics(events, now)
    metrics = metrics_text(m)

    churn_high = (
        m["churn_count"] >= HIGH_CHURN
        or m["churn_rate"] >= HIGH_RATE
    )
    churn_suspicious = (
        m["churn_count"] >= SUSPICIOUS_CHURN
        or m["churn_rate"] >= SUSPICIOUS_RATE
        or m["behavior_anomaly"]
    )
    pull_flood = (
        m["unique_failed_pods"] >= PULL_FLOOD_UNIQUE_PODS
        or m["repeated_failures"] >= PULL_FLOOD_REPEATED_FAILURES
    )

    # Priority 1: resource pressure remains active until an explicit clear event.
    if (
        m["latest_resource_event"] == "RESOURCE_PRESSURE"
        or (
            current_state == "RESOURCE_PRESSURE"
            and m["latest_resource_event"] != "RESOURCE_PRESSURE_CLEARED"
        )
    ):
        recovery_started = None
        return "RESOURCE_PRESSURE", "Resource pressure is active", metrics

    # Priority 2: explicit orphan-pull confirmation from an evidence source.
    if "ORPHAN_PULL_CONFIRMED" in m["recent_types"]:
        recovery_started = None
        return "ORPHAN_PULL", "Confirmed orphan image-pull activity", metrics

    # Priority 3: high churn or a high-volume image-pull failure pattern.
    if churn_high or pull_flood:
        recovery_started = None
        if pull_flood and not churn_high:
            reason = "Image-pull failures reached the configured flood threshold"
        elif pull_flood and churn_high:
            reason = "High Pod churn and image-pull failure activity detected"
        else:
            reason = "Pod churn count or rate reached the high threshold"
        return "PULL_FLOOD", reason, metrics

    # Priority 4: suspicious churn, behavior deviation, or any recent pull failure.
    if churn_suspicious:
        recovery_started = None
        if m["behavior_anomaly"] and m["churn_count"] < SUSPICIOUS_CHURN:
            reason = "Pod churn is unusually high compared with historical behavior"
        elif m["churn_rate"] >= SUSPICIOUS_RATE and m["churn_count"] < SUSPICIOUS_CHURN:
            reason = "Pod churn rate exceeded the suspicious rate threshold"
        else:
            reason = "Pod churn exceeded the suspicious threshold"
        return "SUSPICIOUS", reason, metrics

    if m["pull_failure_count"] > 0:
        recovery_started = None
        if m["long_failure_pods"] > 0:
            reason = "Repeated image-pull failures show a prolonged observed retry span"
        elif m["repeated_failures"] > 0:
            reason = "Repeated image-pull failures detected for one or more Pods"
        else:
            reason = "Recent image-pull failure detected"
        return "SUSPICIOUS", reason, metrics

    # If the policy was already active, do not drop directly to NORMAL.
    # Require a full quiet period first, then a separate stability period.
    if current_state not in {"NORMAL", "RECOVERY"}:
        if m["quiet_seconds"] < RECOVERY_AFTER_SECONDS:
            recovery_started = None
            return (
                current_state,
                f"Holding {current_state}; quiet period "
                f"{int(max(0, m['quiet_seconds']))}/{RECOVERY_AFTER_SECONDS}s",
                metrics,
            )
        recovery_started = None
        return "RECOVERY", "Quiet period completed; beginning stability check", metrics

    if current_state == "RECOVERY":
        # Any new threat/resource event makes quiet_seconds fall below the
        # configured quiet period, which resets the stability timer.
        if m["quiet_seconds"] < RECOVERY_AFTER_SECONDS:
            recovery_started = None
            return (
                "RECOVERY",
                f"New activity reset recovery; quiet period "
                f"{int(max(0, m['quiet_seconds']))}/{RECOVERY_AFTER_SECONDS}s",
                metrics,
            )

        if recovery_started is None:
            recovery_started = time.monotonic()

        stable_seconds = time.monotonic() - recovery_started
        if stable_seconds >= RECOVERY_STABLE_SECONDS:
            recovery_started = None
            return "NORMAL", "Recovery completed; system remained stable", metrics

        return (
            "RECOVERY",
            f"Stability check: {int(stable_seconds)}/{RECOVERY_STABLE_SECONDS}s",
            metrics,
        )

    return "NORMAL", "No suspicious activity detected", metrics


# ==================================================
# POLICY DESCRIPTIONS
# ==================================================

def describe_policy(state):
    policies = {
        "NORMAL": "Monitoring only; no additional restriction requested.",
        "SUSPICIOUS": "Increase monitoring and collect evidence.",
        "ORPHAN_PULL": "Investigate confirmed orphan-pull evidence.",
        "PULL_FLOOD": "Request restrictive Pod admission policy.",
        "RESOURCE_PRESSURE": "Maintain protection and flag resource pressure.",
        "RECOVERY": "Hold current restrictions while quiet and stability are verified.",
    }
    return policies.get(state, "Unknown policy state.")


# ==================================================
# MAIN POLICY ENGINE
# ==================================================

def main():
    global current_state, last_status_log

    current_state = load_state()

    print("Adaptive policy engine started.", flush=True)
    print(f"Namespace: {NAMESPACE}", flush=True)
    print(f"Input: {CSV_FILE}", flush=True)
    print(f"State file: {STATE_FILE}", flush=True)
    print(f"Initial state: {current_state}", flush=True)
    print("DRY RUN: This process will not modify Kubernetes resources.", flush=True)
    print(
        f"Window={WINDOW_SECONDS}s | suspicious churn={SUSPICIOUS_CHURN} "
        f"or {SUSPICIOUS_RATE:.3f}/s | high churn={HIGH_CHURN} "
        f"or {HIGH_RATE:.3f}/s",
        flush=True,
    )
    print(
        f"Baseline={BASELINE_SECONDS}s | behavior multiplier={BASELINE_MULTIPLIER}x "
        f"| baseline floor={BASELINE_RATE_FLOOR:.3f}/s",
        flush=True,
    )
    print(
        f"Pull flood: unique Pods={PULL_FLOOD_UNIQUE_PODS} "
        f"or repeated failures={PULL_FLOOD_REPEATED_FAILURES}",
        flush=True,
    )
    print(
        f"Recovery: {RECOVERY_AFTER_SECONDS}s quiet + "
        f"{RECOVERY_STABLE_SECONDS}s stable",
        flush=True,
    )
    print("Monitoring started.\n", flush=True)

    try:
        while True:
            rows = read_events()
            now = datetime.now(timezone.utc)
            new_state, reason, metrics = select_policy(rows, now)

            if new_state != current_state:
                print(
                    f"\n[{now.isoformat()}] STATE CHANGE: "
                    f"{current_state} -> {new_state}",
                    flush=True,
                )
                print(f"Reason: {reason}", flush=True)
                print(f"Metrics: {metrics}", flush=True)
                print(f"POLICY: {describe_policy(new_state)}\n", flush=True)
                current_state = new_state
                save_state(current_state)
                last_status_log = time.monotonic()
            else:
                if time.monotonic() - last_status_log >= LOG_INTERVAL:
                    print(
                        f"[{now.isoformat()}] STATE: {current_state} | "
                        f"Reason: {reason} | {metrics}",
                        flush=True,
                    )
                    last_status_log = time.monotonic()
                save_state(current_state)

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:
        print("\nAdaptive policy engine stopped.", flush=True)


if __name__ == "__main__":
    main()
