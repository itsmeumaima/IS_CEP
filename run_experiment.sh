
#!/bin/bash

set -u

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE_DIR"

NAMESPACE="image-pull-mitigation-lab"
SELECTOR="app=image-pull-experiment"

# --------------------------------------------------
# CHECK KUBERNETES CONNECTION
# --------------------------------------------------

if ! command -v kubectl >/dev/null 2>&1; then
    echo "ERROR: kubectl is not installed."
    exit 1
fi

if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "ERROR: Namespace is unavailable or Kubernetes is not running."
    exit 1
fi

echo "Connected to namespace: $NAMESPACE"

# --------------------------------------------------
# COMMON FUNCTIONS
# --------------------------------------------------

make_name() {
    echo "$1-$(date +%Y%m%d-%H%M%S)-$RANDOM"
}

check_quota() {
    echo ""
    echo "========== CURRENT POD QUOTA =========="

    if ! kubectl get resourcequota adaptive-pod-limit \
        -n "$NAMESPACE" >/dev/null 2>&1; then
        echo "adaptive-pod-limit quota not found."
        return
    fi

    kubectl get resourcequota adaptive-pod-limit -n "$NAMESPACE"

    read -r USED HARD < <(
        kubectl get resourcequota adaptive-pod-limit \
            -n "$NAMESPACE" \
            -o jsonpath='{.status.used.pods} {.status.hard.pods}'
    )

    USED="${USED:-0}"
    HARD="${HARD:-0}"

    AVAILABLE=$((HARD - USED))

    if [ "$AVAILABLE" -lt 0 ]; then
        AVAILABLE=0
    fi

    echo "Used: $USED / $HARD"
    echo "Available Pod slots: $AVAILABLE"
    echo "======================================="
}

create_pod() {
    local NAME="$1"
    local IMAGE="$2"
    shift 2

    echo ""
    echo "Creating Pod: $NAME"
    echo "Image: $IMAGE"

    if kubectl run "$NAME" \
        --image="$IMAGE" \
        --restart=Never \
        --labels="app=image-pull-experiment,experiment=manual-test" \
        -n "$NAMESPACE" "$@"; then
        echo "Pod creation request accepted: $NAME"
    else
        echo "Pod creation failed: $NAME"
    fi
}

show_status() {
    echo ""
    echo "========== CURRENT PODS =========="

    kubectl get pods -n "$NAMESPACE" -o wide

    echo ""
    echo "========== EXPERIMENT PODS =========="

    kubectl get pods -n "$NAMESPACE" -l "$SELECTOR"

    echo ""
    echo "========== RESOURCE QUOTA =========="

    kubectl get resourcequota adaptive-pod-limit \
        -n "$NAMESPACE" 2>/dev/null || echo "Quota not found."
}

show_events() {
    echo ""
    echo "========== LATEST DETECTOR EVENTS =========="

    if [ -f "$BASE_DIR/detector_events.csv" ]; then
        tail -n 20 "$BASE_DIR/detector_events.csv"
    else
        echo "detector_events.csv not found."
    fi
}

show_policy() {
    echo ""
    echo "========== POLICY STATE FILES =========="

    if [ -f "$BASE_DIR/adaptive_state.txt" ]; then
        echo "Adaptive state:"
        cat "$BASE_DIR/adaptive_state.txt"
    else
        echo "adaptive_state.txt not found."
    fi

    if [ -f "$BASE_DIR/detector_events.csv" ]; then
        echo ""
        echo "Latest events:"
        tail -n 10 "$BASE_DIR/detector_events.csv"
    fi

    echo ""
    echo "Current quota:"
    kubectl get resourcequota adaptive-pod-limit \
        -n "$NAMESPACE" 2>/dev/null || echo "Quota not found."
}

cleanup_experiment_pods() {
    echo ""
    echo "This deletes ONLY Pods labelled:"
    echo "$SELECTOR"

    kubectl get pods -n "$NAMESPACE" -l "$SELECTOR"

    read -rp "Type YES to delete these experiment Pods: " confirm

    if [ "$confirm" = "YES" ]; then
        kubectl delete pods -n "$NAMESPACE" \
            -l "$SELECTOR" --wait=false

        echo "Experiment Pod cleanup requested."
    else
        echo "Cleanup cancelled."
    fi
}

# --------------------------------------------------
# EXPERIMENT 1: NORMAL WORKLOAD
# --------------------------------------------------

normal_test() {
    echo ""
    echo "========== NORMAL WORKLOAD TEST =========="

    check_quota

    for i in 1 2 3; do
        NAME="$(make_name normal-nginx-$i)"
        create_pod "$NAME" "nginx:latest"
    done

    echo ""
    echo "Allow the images to pull and Pods to become Ready."
    echo "Expected: NORMAL, provided there are no other triggers."
}

# --------------------------------------------------
# EXPERIMENT 2: SUSPICIOUS POD CHURN
# --------------------------------------------------

suspicious_test() {
    echo ""
    echo "========== SUSPICIOUS POD CHURN =========="

    check_quota

    echo "Creating and deleting Pods repeatedly."

    for i in {1..6}; do
        NAME="$(make_name suspicious-$i)"

        create_pod "$NAME" "busybox:latest" \
            --command -- sh -c "sleep 60"

        sleep 2

        kubectl delete pod "$NAME" \
            -n "$NAMESPACE" --wait=false \
            --ignore-not-found
    done

    echo ""
    echo "Expected: SUSPICIOUS if the policy's churn threshold is reached."
}

# --------------------------------------------------
# EXPERIMENT 3: INVALID IMAGE PULL
# --------------------------------------------------

invalid_image_test() {
    echo ""
    echo "========== INVALID IMAGE-PULL TEST =========="

    check_quota

    for i in {1..3}; do
        NAME="$(make_name invalid-image-$i)"

        create_pod "$NAME" \
            "invalid-image-does-not-exist-$i:latest"
    done

    echo ""
    echo "Inspect the Pods for ErrImagePull or ImagePullBackOff."
    echo "Expected: SUSPICIOUS if image-pull failures are detected."
}

# --------------------------------------------------
# EXPERIMENT 4: ORPHAN IMAGE PULL
# --------------------------------------------------

orphan_test() {
    echo ""
    echo "========== ORPHAN IMAGE-PULL TEST =========="

    check_quota

    NAME="$(make_name orphan-pull)"

    echo "Creating Pod: $NAME"

    create_pod "$NAME" "debian:bookworm-slim"

    echo ""
    echo "Deleting the Pod immediately to attempt an orphan pull."

    sleep 1

    kubectl delete pod "$NAME" \
        -n "$NAMESPACE" --wait=false \
        --ignore-not-found

    echo ""
    echo "Expected: ORPHAN_PULL only if the detector confirms"
    echo "that the image pull continues after Pod deletion."
    echo "This scenario is timing-dependent."
}

# --------------------------------------------------
# EXPERIMENT 5: LARGE POD CREATION BURST
# --------------------------------------------------

pod_burst_test() {
    echo ""
    echo "========== LARGE POD CREATION BURST =========="

    check_quota

    echo "Attempting to create 12 Pods."

    for i in {1..12}; do
        NAME="$(make_name burst-$i)"

        create_pod "$NAME" "busybox:latest" \
            --command -- sh -c "sleep 120"

        sleep 1
    done

    echo ""
    echo "Expected: PULL_FLOOD if the required churn threshold is reached."
    echo "Some requests may be rejected by ResourceQuota."
}

# --------------------------------------------------
# EXPERIMENT 6: DIFFERENT IMAGES
# --------------------------------------------------

different_images_test() {
    echo ""
    echo "========== DIFFERENT IMAGE TEST =========="

    check_quota

    NAME="$(make_name nginx)"
    create_pod "$NAME" "nginx:latest"

    NAME="$(make_name redis)"
    create_pod "$NAME" "redis:latest"

    NAME="$(make_name busybox)"
    create_pod "$NAME" "busybox:latest" \
        --command -- sh -c "sleep 120"

    NAME="$(make_name debian)"
    create_pod "$NAME" "debian:bookworm-slim"

    echo ""
    echo "Observe the image-pull activity for different images."
}

# --------------------------------------------------
# EXPERIMENT 7: CPU AND MEMORY PRESSURE
# --------------------------------------------------

resource_pressure_test() {
    echo ""
    echo "========== RESOURCE PRESSURE TEST =========="

    check_quota

    NAME="$(make_name resource-test)"

    echo "Creating stress workload: $NAME"

    kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
  labels:
    app: image-pull-experiment
    experiment: resource-test
spec:
  restartPolicy: Never
  containers:
    - name: stress
      image: polinux/stress
      command:
        - stress
      args:
        - "--cpu"
        - "1"
        - "--vm"
        - "1"
        - "--vm-bytes"
        - "100M"
        - "--timeout"
        - "120s"
      resources:
        requests:
          cpu: "100m"
          memory: "64Mi"
        limits:
          cpu: "500m"
          memory: "256Mi"
EOF

    echo ""
    echo "Monitor resource usage using:"
    echo "kubectl top nodes"
    echo "kubectl top pods -n $NAMESPACE"

    echo ""
    echo "Expected: RESOURCE_PRESSURE only if the configured"
    echo "CPU/memory thresholds and duration are reached."
}

# --------------------------------------------------
# EXPERIMENT 8: RECOVERY
# --------------------------------------------------

recovery_test() {
    echo ""
    echo "========== RECOVERY TEST =========="

    echo "No new Pods will be created by this test."
    echo "Stop other attack workloads and wait for resources to settle."

    echo ""
    echo "Current Pods:"
    kubectl get pods -n "$NAMESPACE"

    echo ""
    echo "Current quota:"
    kubectl get resourcequota adaptive-pod-limit \
        -n "$NAMESPACE" 2>/dev/null || echo "Quota not found."

    echo ""
    echo "Recovery observation started."
    echo "Your policy requires its configured quiet and stability periods."
    echo "Keep this system running and observe the dashboard."

    read -rp "Press Enter after the recovery observation period..."
    show_policy
}

# --------------------------------------------------
# EXPERIMENT 9: LARGE-SCALE POD DELETION
# --------------------------------------------------

large_deletion_test() {
    echo ""
    echo "========== LARGE POD DELETION TEST =========="

    echo "Current experiment Pods:"
    kubectl get pods -n "$NAMESPACE" -l "$SELECTOR"

    echo ""
    echo "This test deletes only experiment Pods."
    read -rp "Type YES to delete all experiment Pods: " confirm

    if [ "$confirm" = "YES" ]; then
        kubectl delete pods -n "$NAMESPACE" \
            -l "$SELECTOR" --wait=false

        echo ""
        echo "Deletion requests submitted."
        echo "Observe the detector's Pod deletion events."
    else
        echo "Deletion cancelled."
    fi
}

# --------------------------------------------------
# EXPERIMENT 10: MIXED ATTACK
# --------------------------------------------------

mixed_attack_test() {
    echo ""
    echo "========== MIXED ATTACK TEST =========="

    check_quota

    echo "Creating a combination of valid and invalid image workloads."

    for i in {1..4}; do
        NAME="$(make_name mixed-invalid-$i)"

        create_pod "$NAME" "missing-mixed-image-$i:latest"

        sleep 1
    done

    for i in {1..6}; do
        NAME="$(make_name mixed-burst-$i)"

        create_pod "$NAME" "busybox:latest" \
            --command -- sh -c "sleep 60"

        sleep 1

        kubectl delete pod "$NAME" \
            -n "$NAMESPACE" --wait=false \
            --ignore-not-found
    done

    echo ""
    echo "Mixed workload submitted."
    echo "Observe how the policy classifies the combined activity."
}

# --------------------------------------------------
# EXPERIMENT 11: POD DETAILS
# --------------------------------------------------

pod_details() {
    echo ""
    read -rp "Enter Pod name: " POD_NAME

    if [ -n "$POD_NAME" ]; then
        kubectl describe pod "$POD_NAME" -n "$NAMESPACE"
    else
        echo "Pod name cannot be empty."
    fi
}

# --------------------------------------------------
# MAIN INTERACTIVE MENU
# --------------------------------------------------

while true; do

    echo ""
    echo "================================================"
    echo "       IMAGE PULL DoS EXPERIMENT RUNNER"
    echo "================================================"
    echo "1.  Normal workload test"
    echo "2.  Suspicious Pod creation/deletion"
    echo "3.  Invalid image-pull test"
    echo "4.  Orphan image-pull test"
    echo "5.  Large Pod creation burst"
    echo "6.  Different container images"
    echo "7.  CPU and memory pressure test"
    echo "8.  Recovery observation"
    echo "9.  Large-scale Pod deletion"
    echo "10. Mixed attack test"
    echo "11. View current Pods and quota"
    echo "12. View latest detector events"
    echo "13. View policy state and quota"
    echo "14. View Pod details"
    echo "15. Clean up experiment Pods"
    echo "0.  Exit"
    echo "================================================"

    read -rp "Enter your choice: " choice

    case "$choice" in
        1)  normal_test ;;
        2)  suspicious_test ;;
        3)  invalid_image_test ;;
        4)  orphan_test ;;
        5)  pod_burst_test ;;
        6)  different_images_test ;;
        7)  resource_pressure_test ;;
        8)  recovery_test ;;
        9)  large_deletion_test ;;
        10) mixed_attack_test ;;
        11) show_status ;;
        12) show_events ;;
        13) show_policy ;;
        14) pod_details ;;
        15) cleanup_experiment_pods ;;
        0)
            echo ""
            echo "Experiment runner stopped."
            break
            ;;
        *)
            echo "Invalid choice. Select 0-15."
            ;;
    esac

    echo ""
    echo "========== UPDATED SYSTEM STATUS =========="
    kubectl get pods -n "$NAMESPACE"

    echo ""
    kubectl get resourcequota adaptive-pod-limit \
        -n "$NAMESPACE" 2>/dev/null || echo "Quota not found."

    echo ""
    read -rp "Press Enter to return to the experiment menu..."
done

echo "Goodbye!"
