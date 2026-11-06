import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = Path(os.getenv("POLICY_STATE_FILE", str(BASE_DIR / "adaptive_state.txt")))
HISTORY_FILE = Path(os.getenv("MITIGATION_HISTORY_FILE", str(BASE_DIR / "mitigation_history.jsonl")))

NAMESPACE = os.getenv("MITIGATOR_NAMESPACE", "image-pull-mitigation-lab")
QUOTA_NAME = os.getenv("MITIGATOR_QUOTA_NAME", "adaptive-pod-limit")

POLL_SECONDS = max(1, int(os.getenv("MITIGATOR_POLL_SECONDS", "5")))


def configured_limit(env_name, default):
    value = os.getenv(env_name, str(default)).strip()

    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{env_name} must be a positive integer. "
            "Quota deletion is disabled."
        ) from exc

    if limit < 1:
        raise ValueError(f"{env_name} must be at least 1.")

    return str(limit)


BASELINE_LIMIT = configured_limit("MITIGATOR_BASELINE_LIMIT", "10")
SUSPICIOUS_LIMIT = configured_limit(
    "MITIGATOR_SUSPICIOUS_LIMIT", BASELINE_LIMIT
)
ORPHAN_PULL_LIMIT = configured_limit(
    "MITIGATOR_ORPHAN_PULL_LIMIT", "3"
)
FLOOD_LIMIT = configured_limit("MITIGATOR_FLOOD_LIMIT", "2")
RECOVERY_LIMIT = configured_limit(
    "MITIGATOR_RECOVERY_LIMIT", FLOOD_LIMIT
)
RESOURCE_PRESSURE_LIMIT = configured_limit(
    "MITIGATOR_RESOURCE_PRESSURE_LIMIT", FLOOD_LIMIT
)

STATE_LIMITS = {
    "NORMAL": BASELINE_LIMIT,
    "SUSPICIOUS": SUSPICIOUS_LIMIT,
    "ORPHAN_PULL": ORPHAN_PULL_LIMIT,
    "PULL_FLOOD": FLOOD_LIMIT,
    "RESOURCE_PRESSURE": RESOURCE_PRESSURE_LIMIT,
    "RECOVERY": RECOVERY_LIMIT,
}

VALID_STATES = set(STATE_LIMITS)

# Quota edits are only made to the specifically named ResourceQuota owned by this controller.
# Set MITIGATOR_ALLOW_QUOTA_DELETE=false to prevent automated deletion of that quota.
ALLOW_QUOTA_DELETE = os.getenv("MITIGATOR_ALLOW_QUOTA_DELETE", "true").strip().lower() in {"1", "true", "yes"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_kubernetes():
    try:
        config.load_kube_config()
        print("Loaded local Kubernetes configuration.", flush=True)
    except Exception as local_error:
        try:
            config.load_incluster_config()
            print("Loaded in-cluster Kubernetes configuration.", flush=True)
        except Exception:
            raise RuntimeError(
                "Could not load Kubernetes configuration from kubeconfig or in-cluster credentials."
            ) from local_error


def write_history(action, state, outcome, old_limit=None, desired_limit=None, verified_limit=None, details=""):
    """Append one JSON-lines audit record. History errors are reported, not silently ignored."""
    record = {
        "timestamp": utc_now(),
        "namespace": NAMESPACE,
        "quota_name": QUOTA_NAME,
        "policy_state": state,
        "action": action,
        "outcome": outcome,
        "old_limit": old_limit,
        "desired_limit": desired_limit,
        "verified_limit": verified_limit,
        "details": str(details).replace("\n", " ")[:1000],
    }
    try:
        with HISTORY_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, sort_keys=True) + "\n")
            file.flush()
    except OSError as exc:
        print(f"WARNING: Could not write mitigation history: {exc}", flush=True)
    return record


def read_policy_state():
    try:
        state = STATE_FILE.read_text(encoding="utf-8").strip().upper()
    except FileNotFoundError:
        print(f"WARNING: State file not found: {STATE_FILE}. No quota changes this cycle.", flush=True)
        return None
    except OSError as exc:
        print(f"WARNING: Unable to read policy state: {exc}. No quota changes this cycle.", flush=True)
        return None

    if state not in VALID_STATES:
        print(f"WARNING: Invalid policy state {state!r}. No quota changes this cycle.", flush=True)
        return None
    return state


def validate_limit(value, state):
    """Only allow a positive integer quota limit; None means no quota for that state."""
    if value is None:
        return None
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid Pod quota for state {state}: {value!r}; expected a positive integer or None.") from exc
    if limit < 1:
        raise ValueError(f"Invalid Pod quota for state {state}: {limit}; limit must be at least 1.")
    return str(limit)


def get_current_quota(core):
    """Return (limit, quota_object); None limit means quota absent."""
    try:
        quota = core.read_namespaced_resource_quota(name=QUOTA_NAME, namespace=NAMESPACE)
    except ApiException as exc:
        if exc.status == 404:
            return None, None
        raise

    hard = quota.spec.hard if quota.spec and quota.spec.hard else {}
    pods_limit = hard.get("pods")
    return (str(pods_limit) if pods_limit is not None else None), quota


def verify_quota(core, expected_limit):
    """Re-read the API after a write and verify presence/limit."""
    actual_limit, _ = get_current_quota(core)
    if actual_limit != expected_limit:
        raise RuntimeError(f"Quota verification failed: expected {expected_limit!r}, observed {actual_limit!r}.")
    return actual_limit


def remove_quota(core, state, apply):
    current_limit, _ = get_current_quota(core)
    if current_limit is None:
        print(f"State={state} | Quota already absent; no restriction from {QUOTA_NAME}.", flush=True)
        return

    print(f"State={state} | Current Pod quota={current_limit}.", flush=True)
    if not apply:
        print(f"DRY RUN: Would remove {QUOTA_NAME} (current pods limit={current_limit}).", flush=True)
        write_history("REMOVE_QUOTA", state, "DRY_RUN", current_limit, None, current_limit, "No Kubernetes change made")
        return

    if not ALLOW_QUOTA_DELETE:
        message = "Quota deletion is disabled by MITIGATOR_ALLOW_QUOTA_DELETE=false."
        print(f"SAFEGUARD: {message}", flush=True)
        write_history("REMOVE_QUOTA", state, "BLOCKED", current_limit, None, current_limit, message)
        return

    try:
        core.delete_namespaced_resource_quota(name=QUOTA_NAME, namespace=NAMESPACE)
        verified = verify_quota(core, None)
        print(f"VERIFIED: {QUOTA_NAME} removed; no Pod-count limit is enforced by this controller.", flush=True)
        write_history("REMOVE_QUOTA", state, "SUCCESS_VERIFIED", current_limit, None, verified, "Delete accepted and absence verified by re-reading Kubernetes")
    except Exception as exc:
        print(f"ERROR: Could not remove/verify quota: {exc}", flush=True)
        write_history("REMOVE_QUOTA", state, "FAILED", current_limit, None, None, str(exc))
        # Rollback: best-effort restore the prior quota if deletion may have succeeded but verification failed.
        try:
            actual, _ = get_current_quota(core)
            if actual is None:
                body = client.V1ResourceQuota(
                    metadata=client.V1ObjectMeta(name=QUOTA_NAME, namespace=NAMESPACE),
                    spec=client.V1ResourceQuotaSpec(hard={"pods": current_limit}),
                )
                core.create_namespaced_resource_quota(namespace=NAMESPACE, body=body)
                restored = verify_quota(core, current_limit)
                print(f"ROLLBACK: Restored previous Pod quota={restored} after removal failure.", flush=True)
                write_history("ROLLBACK_RESTORE_QUOTA", state, "SUCCESS_VERIFIED", None, current_limit, restored, "Restored previous limit after failed removal/verification")
        except Exception as rollback_exc:
            print(f"CRITICAL: Quota rollback also failed: {rollback_exc}", flush=True)
            write_history("ROLLBACK_RESTORE_QUOTA", state, "FAILED", None, current_limit, None, str(rollback_exc))


def apply_quota(core, state, desired_limit, apply):
    desired_limit = validate_limit(desired_limit, state)
    if desired_limit is None:
        remove_quota(core, state, apply)
        return

    current_limit, current_quota = get_current_quota(core)
    if current_limit == desired_limit:
        # Still verify by reading from the API (get_current_quota already performed the read).
        print(f"State={state} | Quota already correct and verified: {desired_limit} Pods.", flush=True)
        return

    print(f"State={state} | Quota proposal: {current_limit or 'UNRESTRICTED'} -> {desired_limit} Pods.", flush=True)
    if not apply:
        print("DRY RUN: No Kubernetes changes made.", flush=True)
        write_history("CREATE_OR_UPDATE_QUOTA", state, "DRY_RUN", current_limit, desired_limit, current_limit, "No Kubernetes change made")
        return

    # Safeguard against changing an unexpected quota: only manage our exact quota name and ensure it has a valid spec.
    if current_quota is not None and current_quota.metadata.name != QUOTA_NAME:
        message = "Refusing to modify an unexpected ResourceQuota object."
        print(f"SAFEGUARD: {message}", flush=True)
        write_history("CREATE_OR_UPDATE_QUOTA", state, "BLOCKED", current_limit, desired_limit, current_limit, message)
        return

    old_limit = current_limit
    try:
        if current_quota is None:
            body = client.V1ResourceQuota(
                metadata=client.V1ObjectMeta(
                    name=QUOTA_NAME,
                    namespace=NAMESPACE,
                    labels={"app.kubernetes.io/managed-by": "adaptive-mitigation-controller"},
                ),
                spec=client.V1ResourceQuotaSpec(hard={"pods": desired_limit}),
            )
            core.create_namespaced_resource_quota(namespace=NAMESPACE, body=body)
            action = "CREATE_QUOTA"
        else:
            patch_body = {"spec": {"hard": {"pods": desired_limit}}}
            core.patch_namespaced_resource_quota(name=QUOTA_NAME, namespace=NAMESPACE, body=patch_body)
            action = "UPDATE_QUOTA"

        verified = verify_quota(core, desired_limit)
        print(f"VERIFIED: {action} succeeded; Pod quota is now {verified}.", flush=True)
        write_history(action, state, "SUCCESS_VERIFIED", old_limit, desired_limit, verified, "Change confirmed by re-reading Kubernetes")

    except Exception as exc:
        print(f"ERROR: Failed to create/update quota or verify the result: {exc}", flush=True)
        write_history("CREATE_OR_UPDATE_QUOTA", state, "FAILED", old_limit, desired_limit, None, str(exc))

        # Rollback best-effort: restore the previous value, or remove a newly-created quota.
        try:
            actual_limit, actual_quota = get_current_quota(core)
            if old_limit is None:
                if actual_quota is not None:
                    core.delete_namespaced_resource_quota(name=QUOTA_NAME, namespace=NAMESPACE)
                verify_quota(core, None)
                print("ROLLBACK: Removed newly-created quota after failure.", flush=True)
                write_history("ROLLBACK_REMOVE_NEW_QUOTA", state, "SUCCESS_VERIFIED", actual_limit, None, None, "Restored prior unrestricted state")
            else:
                if actual_quota is None:
                    body = client.V1ResourceQuota(
                        metadata=client.V1ObjectMeta(name=QUOTA_NAME, namespace=NAMESPACE),
                        spec=client.V1ResourceQuotaSpec(hard={"pods": old_limit}),
                    )
                    core.create_namespaced_resource_quota(namespace=NAMESPACE, body=body)
                else:
                    core.patch_namespaced_resource_quota(
                        name=QUOTA_NAME,
                        namespace=NAMESPACE,
                        body={"spec": {"hard": {"pods": old_limit}}},
                    )
                restored = verify_quota(core, old_limit)
                print(f"ROLLBACK: Restored previous quota limit={restored}.", flush=True)
                write_history("ROLLBACK_RESTORE_PREVIOUS_QUOTA", state, "SUCCESS_VERIFIED", actual_limit, old_limit, restored, "Previous quota restored after failed change")
        except Exception as rollback_exc:
            print(f"CRITICAL: Rollback failed: {rollback_exc}", flush=True)
            write_history("ROLLBACK", state, "FAILED", old_limit, desired_limit, None, str(rollback_exc))


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Adaptive Mitigation Controller")
    parser.add_argument("--apply", action="store_true", help="Apply quota changes to Kubernetes; default is dry-run.")
    args = parser.parse_args()

    # Validate configured limits before connecting or making any changes.
    for state, limit in STATE_LIMITS.items():
        validate_limit(limit, state)

    print("\nAdaptive Mitigation Controller")
    print("--------------------------------")
    print(f"Namespace: {NAMESPACE}")
    print(f"Quota: {QUOTA_NAME}")
    print(f"State file: {STATE_FILE}")
    print(f"History file: {HISTORY_FILE}")
    print(f"Apply mode: {'ENABLED' if args.apply else 'DRY RUN'}")
    print(f"Polling interval: {POLL_SECONDS} seconds")
    print("State limits: " + ", ".join(f"{s}={'UNRESTRICTED' if l is None else l}" for s, l in STATE_LIMITS.items()))
    if not args.apply:
        print("DRY RUN: Kubernetes resources will not be modified.")

    load_kubernetes()
    core = client.CoreV1Api()
    previous_state = None

    try:
        while True:
            state = read_policy_state()
            if state is None:
                time.sleep(POLL_SECONDS)
                continue

            if state != previous_state:
                print(f"\nPOLICY STATE CHANGE: {previous_state or 'UNKNOWN'} -> {state}", flush=True)
                previous_state = state

            desired_limit = STATE_LIMITS[state]
            # State-specific action messages use the actual state, never a hard-coded NORMAL label.
            if desired_limit is None:
                print(f"State={state} | Action=REMOVE QUOTA (unrestricted state)", flush=True)
            else:
                print(f"State={state} | Action=ENFORCE POD LIMIT {desired_limit}", flush=True)

            try:
                apply_quota(core, state, desired_limit, args.apply)
            except ApiException as exc:
                message = f"Kubernetes API error {exc.status} {exc.reason}"
                print(message, flush=True)
                write_history("CONTROLLER_CYCLE", state, "FAILED", details=message)
            except Exception as exc:
                message = f"Controller cycle failed: {type(exc).__name__}: {exc}"
                print(message, flush=True)
                write_history("CONTROLLER_CYCLE", state, "FAILED", details=message)

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:
        print("\nAdaptive Mitigation Controller stopped.", flush=True)


if __name__ == "__main__":
    main()
