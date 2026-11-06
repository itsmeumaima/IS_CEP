import csv
import os
import time
import hashlib
from collections import deque
from datetime import datetime, timezone

from kubernetes import client, config, watch
from kubernetes.client.exceptions import ApiException

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

NAMESPACE = os.getenv(
    "DETECTOR_NAMESPACE",
    "image-pull-mitigation-lab"
)

WINDOW_SECONDS = int(os.getenv("DETECTOR_WINDOW_SECONDS", "120"))
SUSPICIOUS_CHURN = int(os.getenv("DETECTOR_SUSPICIOUS_CHURN", "5"))
HIGH_CHURN = int(os.getenv("DETECTOR_HIGH_CHURN", "10"))

CSV_FILE = os.path.join(BASE_DIR, "detector_events.csv")

CHURN_EVENTS = {"POD_CREATED", "POD_DELETED"}
IMAGE_PULL_FAILURES = {"ErrImagePull", "ImagePullBackOff"}
IMAGE_PULL_WAITING = IMAGE_PULL_FAILURES | {"ContainerCreating", "PodInitializing"}

# CSV keeps the original columns and adds structured fields.
CSV_FIELDS = [
    "timestamp",
    "namespace",
    "pod",
    "event_type",
    "reason",
    "churn_60s",  # legacy column name retained for policy compatibility
    "severity",
    "details",
    "pod_uid",
    "container",
    "image",
    "image_source",
    "failure_count",
    "dedupe_key",
]

# Sliding-window churn events: (monotonic_time, event_id)
churn = deque()

# UID -> last observed Pod snapshot
last_pod_state = {}

# (Pod UID, container name) -> last pull-related state
last_container_pull_state = {}

# (Pod UID, container name, reason) -> count of distinct failure transitions
failure_counts = {}

# Event keys already written during this process; bounded to avoid unbounded growth.
seen_event_keys = set()
seen_event_order = deque()
MAX_DEDUPE_KEYS = 20000


# --------------------------------------------------
# TIMESTAMP AND HELPERS
# --------------------------------------------------

def timestamp():
    return datetime.now(timezone.utc).isoformat()


def safe_text(value, limit=500):
    return str(value or "").replace("\n", " ").replace("\r", " ")[:limit]


def pod_uid(pod):
    return (getattr(pod.metadata, "uid", None) or pod.metadata.name or "")


def image_source(image):
    """Return a best-effort registry/source label from an image reference."""
    if not image:
        return ""

    first = image.split("/", 1)[0]
    # A first path component containing '.' or ':' or equal to localhost
    # is conventionally a registry host; otherwise use the default registry.
    if "." in first or ":" in first or first == "localhost":
        return first
    return "default-registry (implicit)"


def dedupe_key(*parts):
    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def remember_event_key(key):
    if key in seen_event_keys:
        return False

    seen_event_keys.add(key)
    seen_event_order.append(key)

    while len(seen_event_order) > MAX_DEDUPE_KEYS:
        old = seen_event_order.popleft()
        seen_event_keys.discard(old)

    return True


# --------------------------------------------------
# CSV LOGGING
# --------------------------------------------------

def write_csv(record):
    exists = os.path.exists(CSV_FILE)
    needs_header = not exists or os.path.getsize(CSV_FILE) == 0

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=CSV_FIELDS,
            extrasaction="ignore",
        )

        if needs_header:
            writer.writeheader()

        writer.writerow(record)
        file.flush()


# --------------------------------------------------
# EVENT DETECTION AND LOGGING
# --------------------------------------------------

def record_event(
    pod,
    event_type,
    reason="",
    details="",
    uid="",
    container="",
    image="",
    failure_count_value="",
    event_identity="",
):
    now = time.monotonic()

    while churn and now - churn[0][0] > WINDOW_SECONDS:
        churn.popleft()

    # Use stable event identity where available to avoid double-counting
    # the same lifecycle event when watch streams reconnect.
    event_key = dedupe_key(
        NAMESPACE,
        uid,
        event_type,
        reason,
        container,
        image,
        event_identity or details,
    )

    if not remember_event_key(event_key):
        print(
            f"DEDUPLICATED type={event_type} pod={pod or '-'} "
            f"reason={reason or '-'}",
            flush=True,
        )
        return False

    if event_type in CHURN_EVENTS:
        churn.append((now, event_key))

    churn_count = len(churn)

    if reason in IMAGE_PULL_FAILURES or event_type == "IMAGE_PULL_FAILURE":
        severity = "SUSPICIOUS"
    elif churn_count >= HIGH_CHURN:
        severity = "HIGH"
    elif churn_count >= SUSPICIOUS_CHURN:
        severity = "SUSPICIOUS"
    else:
        severity = "NORMAL"

    record = {
        "timestamp": timestamp(),
        "namespace": NAMESPACE,
        "pod": pod or "",
        "event_type": event_type,
        "reason": reason or "",
        "churn_60s": churn_count,
        "severity": severity,
        "details": safe_text(details),
        "pod_uid": uid or "",
        "container": container or "",
        "image": image or "",
        "image_source": image_source(image),
        "failure_count": failure_count_value,
        "dedupe_key": event_key,
    }

    write_csv(record)

    print(
        f"[{record['timestamp']}] "
        f"{severity:<10} "
        f"type={event_type} "
        f"pod={pod or '-'} "
        f"container={container or '-'} "
        f"reason={reason or '-'} "
        f"churn_{WINDOW_SECONDS}s={churn_count}",
        flush=True,
    )
    return True


# --------------------------------------------------
# IMAGE-PULL STATUS OBSERVATION
# --------------------------------------------------

def inspect_pod(pod):
    """
    Inspect current container statuses.

    Kubernetes status gives observations such as waiting reasons and image
    fields. These are not direct containerd pull-start/completion timestamps.
    """
    name = pod.metadata.name
    uid = pod_uid(pod)
    phase = pod.status.phase if pod.status else "Unknown"
    spec_containers = {}

    if pod.spec:
        for container_spec in (
            (pod.spec.init_containers or [])
            + (pod.spec.containers or [])
            + (pod.spec.ephemeral_containers or [])
        ):
            spec_containers[container_spec.name] = container_spec.image or ""

    current_states = {}

    if pod.status:
        statuses = (
            (pod.status.init_container_statuses or [])
            + (pod.status.container_statuses or [])
            + (pod.status.ephemeral_container_statuses or [])
        )

        for status in statuses:
            container_name = status.name or ""
            image = status.image or spec_containers.get(container_name, "")
            waiting = status.state.waiting if status.state else None
            running = status.state.running if status.state else None
            terminated = status.state.terminated if status.state else None

            if waiting and waiting.reason in IMAGE_PULL_FAILURES:
                state_label = waiting.reason
                message = waiting.message or ""
            elif running:
                state_label = "RUNNING"
                message = ""
            elif terminated:
                state_label = "TERMINATED"
                message = terminated.reason or ""
            elif waiting:
                state_label = waiting.reason or "WAITING"
                message = waiting.message or ""
            else:
                state_label = "UNKNOWN"
                message = ""

            current_states[container_name] = {
                "state": state_label,
                "image": image,
                "message": message,
            }

            state_key = (uid, container_name)
            old_state = last_container_pull_state.get(state_key)
            old_label = old_state.get("state") if old_state else None

            # Emit only transitions into/out of image-pull failure states.
            if state_label in IMAGE_PULL_FAILURES and old_label != state_label:
                failure_key = (uid, container_name, state_label)
                failure_counts[failure_key] = failure_counts.get(failure_key, 0) + 1
                count = failure_counts[failure_key]

                record_event(
                    name,
                    "IMAGE_PULL_FAILURE",
                    reason=state_label,
                    details=(
                        f"phase={phase}; observed_container_state={state_label}; "
                        f"message={message}; failure_count_for_reason={count}"
                    ),
                    uid=uid,
                    container=container_name,
                    image=image,
                    failure_count_value=count,
                    event_identity=f"{state_label}:{count}",
                )

            # Best-effort lifecycle signals based on Kubernetes-visible state.
            # These do not claim to be exact runtime pull timestamps.
            if state_label in IMAGE_PULL_WAITING and old_label not in IMAGE_PULL_WAITING:
                record_event(
                    name,
                    "IMAGE_PULL_ACTIVITY_OBSERVED",
                    reason=state_label,
                    details=(
                        f"Observed image-related waiting state; phase={phase}; "
                        "Kubernetes status does not confirm exact runtime pull start"
                    ),
                    uid=uid,
                    container=container_name,
                    image=image,
                    event_identity=f"waiting-enter:{state_label}",
                )

            if old_label in IMAGE_PULL_WAITING and state_label not in IMAGE_PULL_WAITING:
                event_name = (
                    "IMAGE_PULL_FAILURE_CLEARED"
                    if old_label in IMAGE_PULL_FAILURES
                    else "IMAGE_PULL_WAITING_ENDED"
                )
                record_event(
                    name,
                    event_name,
                    reason=state_label,
                    details=(
                        f"Image-related waiting state changed from {old_label} "
                        f"to {state_label}; this is an observed status transition, "
                        "not proof of exact image-pull completion"
                    ),
                    uid=uid,
                    container=container_name,
                    image=image,
                    event_identity=f"waiting-exit:{old_label}:{state_label}",
                )

            last_container_pull_state[state_key] = {
                "state": state_label,
                "image": image,
            }

    # Remove stale per-container observations for this Pod.
    active_names = set(current_states)
    for state_key in list(last_container_pull_state):
        if state_key[0] == uid and state_key[1] not in active_names:
            del last_container_pull_state[state_key]

    return {
        "phase": phase,
        "uid": uid,
        "images": spec_containers,
        "container_states": current_states,
        "resource_version": getattr(pod.metadata, "resource_version", None),
    }


# --------------------------------------------------
# KUBERNETES CONNECTION
# --------------------------------------------------

def load_kubernetes_config():
    try:
        config.load_kube_config()
        print("Loaded local Kubernetes configuration.", flush=True)
    except Exception:
        config.load_incluster_config()
        print("Loaded in-cluster Kubernetes configuration.", flush=True)


# --------------------------------------------------
# MAIN DETECTOR
# --------------------------------------------------

def main():
    load_kubernetes_config()
    core = client.CoreV1Api()

    print("\nImage Pull DoS Detector Started")
    print("--------------------------------")
    print(f"Namespace: {NAMESPACE}")
    print(f"CSV output: {CSV_FILE}")
    print(f"Monitoring window: {WINDOW_SECONDS} seconds")
    print(f"Suspicious churn threshold: {SUSPICIOUS_CHURN}")
    print(f"High churn threshold: {HIGH_CHURN}")
    print("Image-pull lifecycle: Kubernetes status observations, not direct runtime timings.")
    print("Detection only: no Kubernetes resources will be changed.")
    print("Press Ctrl+C to stop.\n", flush=True)

    record_event(
        "",
        "DETECTOR_STARTED",
        details="Detector process started",
        event_identity="process-start",
    )

    resource_version = None
    initial_snapshot_done = False

    while True:
        stream = watch.Watch()

        try:
            if not initial_snapshot_done:
                pods = core.list_namespaced_pod(namespace=NAMESPACE)
                resource_version = pods.metadata.resource_version

                for pod in pods.items:
                    uid = pod_uid(pod)
                    snapshot = inspect_pod(pod)

                    # Store initial state without counting existing Pods as churn.
                    last_pod_state[uid] = snapshot

                initial_snapshot_done = True
                print("Initial Pod snapshot collected.", flush=True)

            for event in stream.stream(
                core.list_namespaced_pod,
                namespace=NAMESPACE,
                resource_version=resource_version,
                timeout_seconds=60,
                allow_watch_bookmarks=True,
            ):
                event_type = event["type"]
                pod = event["object"]

                if event_type == "BOOKMARK":
                    metadata = getattr(pod, "metadata", None)
                    if metadata and metadata.resource_version:
                        resource_version = metadata.resource_version
                    continue

                if event_type == "ERROR":
                    print(f"Kubernetes watch error: {pod}", flush=True)
                    if getattr(pod, "code", None) == 410:
                        print(
                            "Resource version expired. A fresh snapshot is required.",
                            flush=True,
                        )
                        initial_snapshot_done = False
                        resource_version = None
                    break

                if not getattr(pod, "metadata", None) or not pod.metadata.name:
                    continue

                if pod.metadata.resource_version:
                    resource_version = pod.metadata.resource_version

                name = pod.metadata.name
                uid = pod_uid(pod)

                if event_type == "ADDED":
                    snapshot = inspect_pod(pod)
                    existed = uid in last_pod_state
                    last_pod_state[uid] = snapshot

                    if not existed:
                        images = sorted(set(snapshot["images"].values()))
                        record_event(
                            name,
                            "POD_CREATED",
                            details=(
                                f"phase={snapshot['phase']}; "
                                f"images={','.join(images)}"
                            ),
                            uid=uid,
                            image=",".join(images),
                            event_identity=f"pod-added:{uid}",
                        )

                elif event_type == "MODIFIED":
                    snapshot = inspect_pod(pod)
                    old_snapshot = last_pod_state.get(uid)
                    old_phase = (
                        old_snapshot.get("phase")
                        if isinstance(old_snapshot, dict)
                        else old_snapshot
                    )

                    if snapshot["phase"] != old_phase:
                        record_event(
                            name,
                            "POD_PHASE_CHANGED",
                            details=(
                                f"{old_phase or 'Unknown'} -> {snapshot['phase']}"
                            ),
                            uid=uid,
                            event_identity=f"phase:{old_phase}->{snapshot['phase']}",
                        )

                    last_pod_state[uid] = snapshot

                elif event_type == "DELETED":
                    old_snapshot = last_pod_state.pop(uid, None)

                    # Include the last known image references when available.
                    old_images = []
                    if isinstance(old_snapshot, dict):
                        old_images = sorted(set(old_snapshot.get("images", {}).values()))

                    record_event(
                        name,
                        "POD_DELETED",
                        details=(
                            "Deletion observed; orphaned pull is not confirmed; "
                            f"last_known_images={','.join(old_images)}"
                        ),
                        uid=uid,
                        image=",".join(old_images),
                        event_identity=f"pod-deleted:{uid}",
                    )

                    # Keep pull-state history for the same UID only until deletion;
                    # a later Pod with a new UID is tracked independently.
                    for state_key in list(last_container_pull_state):
                        if state_key[0] == uid:
                            del last_container_pull_state[state_key]

        except ApiException as exc:
            print(
                f"Kubernetes API error: {exc.status} {exc.reason}",
                flush=True,
            )
            if exc.status == 410:
                initial_snapshot_done = False
                resource_version = None

        except KeyboardInterrupt:
            print("\nDetector stopped.", flush=True)
            break

        except Exception as exc:
            print(
                f"Watch interrupted: {type(exc).__name__}: {exc}",
                flush=True,
            )

        finally:
            stream.stop()

        print(
            "Reconnecting to Kubernetes Pod watch in 3 seconds...",
            flush=True,
        )
        time.sleep(3)


if __name__ == "__main__":
    main()
