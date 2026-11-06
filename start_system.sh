
#!/bin/bash

set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE_DIR"

NAMESPACE="image-pull-mitigation-lab"
LOG_DIR="$BASE_DIR/logs"
PID_DIR="$BASE_DIR/pids"

mkdir -p "$LOG_DIR" "$PID_DIR"

export DETECTOR_NAMESPACE="$NAMESPACE"
export MITIGATOR_NAMESPACE="$NAMESPACE"
export POLICY_NAMESPACE="$NAMESPACE"

echo "======================================"
echo " Image Pull DoS Defense System"
echo "======================================"

# Check required commands
for cmd in python kubectl minikube; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is not installed or not in PATH."
        exit 1
    fi
done

# Check Minikube
if ! minikube status >/dev/null 2>&1; then
    echo "ERROR: Minikube is not running."
    echo "Start it using: minikube start"
    exit 1
fi

# Check Kubernetes context
if [ "$(kubectl config current-context)" != "minikube" ]; then
    echo "ERROR: Kubernetes context is not minikube."
    exit 1
fi

# Check namespace
if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "ERROR: Namespace $NAMESPACE does not exist."
    exit 1
fi

echo "Minikube and namespace checks passed."

start_process() {
    NAME="$1"
    shift

    PID_FILE="$PID_DIR/$NAME.pid"
    LOG_FILE="$LOG_DIR/$NAME.log"

    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "$NAME is already running (PID $OLD_PID)."
            return
        fi
        rm -f "$PID_FILE"
    fi

    nohup "$@" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"

    sleep 2

    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Started $NAME."
    else
        echo "ERROR: $NAME failed to start. Check $LOG_FILE"
        rm -f "$PID_FILE"
    fi
}

echo ""
echo "Starting monitoring components..."

start_process detector python -u detector.py
start_process resource_monitor python -u resource_monitor.py
start_process adaptive_policy python -u adaptive_policy.py
start_process adaptive_controller python -u adaptive_controller.py --apply

echo ""
echo "Starting Streamlit dashboard..."

start_process dashboard python -m streamlit run app.py --server.headless true

echo ""
echo "======================================"
echo " Startup commands completed."
echo " Dashboard: http://localhost:8501"
echo " Logs: $LOG_DIR"
echo "======================================"
