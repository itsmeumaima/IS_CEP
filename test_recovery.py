
import adaptive_policy as policy
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

# No recent events; the latest churn event was 3 minutes ago.
now = datetime.now(timezone.utc)
old_event = {
    "timestamp": (now - timedelta(seconds=180)).isoformat(),
    "namespace": policy.NAMESPACE,
    "event_type": "POD_CREATED",
    "severity": "NORMAL",
}

policy.current_state = "PULL_FLOOD"
policy.recovery_started = None

# Force the policy engine to read one old event and simulate
# the quiet period having elapsed.
with patch.object(policy, "read_events", return_value=[old_event]):
    state, churn = policy.select_policy([], now)

print(f"Recovery transition result: {state}")
print(f"Recent churn: {churn}")

# Verify that the policy entered RECOVERY.
assert state == "RECOVERY", f"Expected RECOVERY, got {state}"

# Simulate 31 seconds of stable recovery.
policy.current_state = "RECOVERY"
policy.recovery_started = 100.0

with patch("adaptive_policy.time.monotonic", return_value=131.0):
    with patch.object(policy, "read_events", return_value=[old_event]):
        state, churn = policy.select_policy([], now)

print(f"Final transition result: {state}")
assert state == "NORMAL", f"Expected NORMAL, got {state}"

print("PASS: PULL_FLOOD -> RECOVERY -> NORMAL")
