import os
import subprocess
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

try:
    from kubernetes import client, config
except ImportError:
    client = None
    config = None


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, "detector_events.csv")
POLICY_STATE_FILE = os.path.join(BASE_DIR, "adaptive_state.txt")

NAMESPACE = os.getenv(
    "DASHBOARD_NAMESPACE",
    "image-pull-mitigation-lab"
)
QUOTA_NAME = "adaptive-pod-limit"

DETECTION_WINDOW_SECONDS = 120
REFRESH_INTERVAL_MS = 5000
CPU_THRESHOLD = 80
MEMORY_THRESHOLD = 80

VALID_POLICY_STATES = {
    "NORMAL",
    "SUSPICIOUS",
    "PULL_FLOOD",
    "RECOVERY",
    "ORPHAN_PULL",
    "RESOURCE_PRESSURE",
}

# Consistent status palette used across cards, charts and labels.
COLORS = {
    "NORMAL": "#4F8068",
    "INFO": "#4F8068",
    "RECOVERY": "#688A9B",
    "SUSPICIOUS": "#B88945",
    "RESOURCE_PRESSURE": "#B97855",
    "ORPHAN_PULL": "#81749A",
    "PULL_FLOOD": "#B65F5A",
    "HIGH": "#B65F5A",
    "UNKNOWN": "#8A918B",
    "UNAVAILABLE": "#8A918B",
    "BACKGROUND": "#F4F3EE",
    "SURFACE": "#FFFFFF",
    "NAVY": "#34443B",
    "TEXT": "#354139",
    "MUTED": "#7B847D",
    "BORDER": "#E3E5DE",
    "ACCENT": "#64816D",
}


# ------------------------------------------------------------
# Page setup and styling
# ------------------------------------------------------------

st.set_page_config(
    page_title="Image Pull Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st_autorefresh(
    interval=REFRESH_INTERVAL_MS,
    key="image_pull_dashboard_refresh"
)

st.markdown(
    """
    <style>
    header[data-testid="stHeader"] {
        background-color: #34443B !important;
    }

    [data-testid="stToolbar"] {
        background-color: ##34443B !important;
    }

    [data-testid="stDecoration"] {
        background-color: ##34443B !important;
    }
    :root {
        --page: #F4F3EE;
        --surface: #FFFFFF;
        --ink: #354139;
        --muted: #7B847D;
        --line: #E3E5DE;
        --accent: #64816D;
    }
    .stApp { background: var(--page); color: var(--ink); }
    [data-testid="stSidebar"] { display: none; }
    [data-testid="collapsedControl"] { display: none; }
    .block-container { padding-top: 1.5rem; padding-bottom: 2.5rem; max-width: 1480px; }
    .main-title {
        color: #34443B; font-size: 2rem; font-weight: 780;
        letter-spacing: -0.04em; line-height: 1.2; margin-bottom: .25rem;
    }
    .sub-title { color: #7B847D; font-size: .92rem; margin-bottom: 1.2rem; }
    .metric-card {
        background: #FFFFFF; border: 1px solid #E3E5DE;
        border-radius: 14px; padding: 16px 18px; min-height: 108px;
        box-shadow: 0 3px 12px rgba(53,65,57,.045);
    }
    .metric-label { color: #7B847D; font-size: .70rem; font-weight: 750; letter-spacing: .07em; }
    .metric-value { color: #34443B; font-size: 1.48rem; font-weight: 780; margin-top: 7px; overflow-wrap: anywhere; }
    .metric-note { color: #7B847D; font-size: .76rem; margin-top: 4px; }
    .section-title { color: #34443B; font-size: 1.12rem; font-weight: 750; margin: .25rem 0 .65rem; }
    div[data-testid="stDataFrame"] { border: 1px solid #E3E5DE; border-radius: 12px; overflow: hidden; }
    div[data-testid="stMetric"] { background: #FFFFFF; border: 1px solid #E3E5DE; border-radius: 12px; padding: 12px 15px; }
    div.stButton > button, div.stFormSubmitButton > button {
        border-radius: 10px; font-weight: 650; min-height: 2.55rem;
        border: 1px solid #D7DDD5;
    }
    div.stButton > button[kind="primary"], div.stFormSubmitButton > button[kind="primary"] {
        background: #64816D; border-color: #64816D; color: white;
    }
    div[data-testid="stTabs"] button { font-weight: 650; }
    .stAlert { border-radius: 11px; }
    hr { border-color: #E3E5DE; }
    input, textarea, [data-baseweb="select"] > div { border-radius: 9px !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def memory_to_mib(value):
    """Convert Kubernetes memory quantities to MiB."""
    value = str(value).strip()

    units = {
        "Ki": 1 / 1024,
        "Mi": 1,
        "Gi": 1024,
        "Ti": 1024 * 1024,
        "K": 1 / 1024,
        "M": 1,
        "G": 1024,
        "T": 1024 * 1024,
    }

    for unit, multiplier in units.items():
        if value.endswith(unit):
            return float(value[:-len(unit)]) * multiplier

    return float(value) / (1024 * 1024)


def cpu_to_cores(value):
    """Convert Kubernetes CPU quantities to CPU cores."""
    value = str(value).strip()

    if value.endswith("n"):
        return float(value[:-1]) / 1_000_000_000
    if value.endswith("u"):
        return float(value[:-1]) / 1_000_000
    if value.endswith("m"):
        return float(value[:-1]) / 1000

    return float(value)


def metric_card(label, value, note="", color=None):
    accent = color or COLORS["ACCENT"]
    return f"""
    <div class="metric-card" style="border-top: 4px solid {accent};">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-note">{note}</div>
    </div>
    """


def section_title(value):
    st.markdown(
        f'<div class="section-title">{value}</div>',
        unsafe_allow_html=True
    )


def show_page_title(title, subtitle=""):
    st.markdown(
        f'<div class="main-title">{title}</div>',
        unsafe_allow_html=True
    )
    if subtitle:
        st.markdown(
            f'<div class="sub-title">{subtitle}</div>',
            unsafe_allow_html=True
        )


def status_color(value):
    return COLORS.get(str(value).upper(), COLORS["UNKNOWN"])


def read_policy_state():
    try:
        with open(POLICY_STATE_FILE, "r", encoding="utf-8") as file:
            state = file.read().strip().upper()
        return state if state in VALID_POLICY_STATES else "UNKNOWN"
    except OSError:
        return "UNAVAILABLE"


def format_time(value):
    if pd.isna(value):
        return "—"
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (AttributeError, ValueError):
        return str(value)


@st.cache_data(ttl=2, show_spinner=False)
def load_events(path, modified_time):
    columns = [
        "timestamp",
        "namespace",
        "pod",
        "event_type",
        "reason",
        "churn_60s",
        "severity",
        "details",
    ]

    if not os.path.exists(path):
        return pd.DataFrame(columns=columns)

    try:
        df = pd.read_csv(path)
    except (
        OSError,
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
    ):
        return pd.DataFrame(columns=columns)

    for column in columns:
        if column not in df.columns:
            df[column] = ""

    df = df[columns].copy()
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True
    )
    df["churn_60s"] = pd.to_numeric(
        df["churn_60s"],
        errors="coerce"
    ).fillna(0).astype(int)

    for column in [
        "namespace",
        "pod",
        "event_type",
        "reason",
        "severity",
        "details",
    ]:
        df[column] = df[column].fillna("").astype(str)

    return (
        df.dropna(subset=["timestamp"])
        .sort_values("timestamp", ascending=False)
    )


# ------------------------------------------------------------
# Kubernetes access
# ------------------------------------------------------------

@st.cache_resource(show_spinner=False)
def get_k8s_api():
    if client is None or config is None:
        return None, None, "Kubernetes Python package is not installed."

    try:
        config.load_kube_config()
        return client.CoreV1Api(), client, None
    except Exception as exc:
        return None, None, f"Could not load Kubernetes configuration: {exc}"


def get_cluster_data():
    api, _, error = get_k8s_api()

    if api is None:
        return [], None, error

    pods = []
    quota = None

    try:
        pod_list = api.list_namespaced_pod(namespace=NAMESPACE)

        for pod in pod_list.items:
            container_statuses = pod.status.container_statuses or []
            waiting_reasons = []

            for container_status in container_statuses:
                state = container_status.state
                if state and state.waiting and state.waiting.reason:
                    waiting_reasons.append(state.waiting.reason)

            pods.append({
                "Pod": pod.metadata.name or "",
                "Status": pod.status.phase or "Unknown",
                "Ready": sum(
                    1 for item in container_statuses if item.ready
                ),
                "Containers": len(pod.spec.containers or []),
                "Restarts": sum(
                    item.restart_count or 0 for item in container_statuses
                ),
                "Node": pod.spec.node_name or "",
                "Reason": ", ".join(waiting_reasons)
                    or (pod.status.reason or ""),
                "Created": pod.metadata.creation_timestamp,
            })

    except Exception as exc:
        error = f"Could not read Pods: {exc}"

    try:
        quota_obj = api.read_namespaced_resource_quota(
            name=QUOTA_NAME,
            namespace=NAMESPACE
        )

        hard = quota_obj.status.hard or {}
        used = quota_obj.status.used or {}

        quota = {
            "name": quota_obj.metadata.name,
            "hard_pods": int(hard.get("pods", 0)),
            "used_pods": int(used.get("pods", 0)),
            "hard": {str(k): str(v) for k, v in hard.items()},
            "used": {str(k): str(v) for k, v in used.items()},
        }

    except Exception as exc:
        if not error:
            error = f"Could not read ResourceQuota: {exc}"

    return pods, quota, error


def get_resource_metrics():
    """Read node CPU and memory usage from Kubernetes Metrics Server."""
    api, k8s_client, error = get_k8s_api()

    if api is None:
        return [], error

    try:
        metrics_api = k8s_client.CustomObjectsApi()

        result = metrics_api.list_cluster_custom_object(
            group="metrics.k8s.io",
            version="v1beta1",
            plural="nodes",
        )

        node_metrics = []

        for item in result.get("items", []):
            node_name = item["metadata"]["name"]
            usage = item.get("usage", {})

            cpu_cores = cpu_to_cores(usage.get("cpu", "0"))
            memory_mib = memory_to_mib(usage.get("memory", "0"))

            node = api.read_node(node_name)
            capacity = node.status.capacity or {}

            cpu_capacity = cpu_to_cores(capacity.get("cpu", "1"))
            memory_capacity_mib = memory_to_mib(
                capacity.get("memory", "1Gi")
            )

            cpu_percent = (
                cpu_cores / cpu_capacity * 100
                if cpu_capacity else 0
            )
            memory_percent = (
                memory_mib / memory_capacity_mib * 100
                if memory_capacity_mib else 0
            )

            node_metrics.append({
                "Node": node_name,
                "CPU Usage": f"{cpu_cores * 1000:.0f}m",
                "CPU Percent": round(cpu_percent, 1),
                "Memory Usage": f"{memory_mib:.0f} MiB",
                "Memory Percent": round(memory_percent, 1),
            })

        return node_metrics, None

    except Exception as exc:
        return [], f"Could not retrieve resource metrics: {exc}"


# ------------------------------------------------------------
# Load current data
# ------------------------------------------------------------

try:
    csv_mtime = (
        os.path.getmtime(CSV_FILE)
        if os.path.exists(CSV_FILE)
        else 0
    )
except OSError:
    csv_mtime = 0

all_events = load_events(CSV_FILE, csv_mtime)

if not all_events.empty:
    events = all_events[
        all_events["namespace"].eq(NAMESPACE)
    ].copy()
else:
    events = all_events.copy()



policy_state = read_policy_state()
pods, quota, cluster_error = get_cluster_data()
resource_metrics, metrics_error = get_resource_metrics()

now_utc = pd.Timestamp.now(tz="UTC")
window_start = now_utc - pd.Timedelta(
    seconds=DETECTION_WINDOW_SECONDS
)

window_events = (
    events[events["timestamp"] >= window_start]
    if not events.empty
    else events
)

current_churn = len(window_events)

# ------------------------------------------------------------
# Experiment runner (runs directly from the dashboard)
# ------------------------------------------------------------

EXPERIMENT_SELECTOR = "app=image-pull-experiment"


def kubectl_run(arguments, input_text=None, timeout=45):
    """Run kubectl safely without a separate shell script."""
    try:
        result = subprocess.run(
            ["kubectl", *arguments],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return False, "kubectl was not found. Install kubectl and add it to PATH."
    except subprocess.TimeoutExpired:
        return False, "kubectl command timed out."
    output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    return result.returncode == 0, output or ("Command completed." if result.returncode == 0 else "Command failed.")


def experiment_name(prefix):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = int(time.time() * 1000) % 100000
    return f"{prefix}-{stamp}-{suffix}"[:63].rstrip("-")


def create_experiment_pod(name, image, command_args=None, resources=None):
    args = [
        "run", name, f"--image={image}", "--restart=Never",
        f"--labels={EXPERIMENT_SELECTOR},experiment=manual-test",
        "-n", NAMESPACE,
    ]
    if resources:
        args.extend(resources)
    if command_args:
        args.extend(["--", *command_args])
    return kubectl_run(args)


def delete_experiment_pod(name):
    return kubectl_run([
        "delete", "pod", name, "-n", NAMESPACE,
        "--wait=false", "--ignore-not-found",
    ])


def execute_experiment(kind, image, pod_count, interval, duration, cpu_count, memory_size):
    """Execute the selected experiment using values entered in the UI."""
    outputs = []
    successes = 0

    if kind == "Normal workload":
        for i in range(pod_count):
            name = experiment_name(f"normal-{i + 1}")
            ok, message = create_experiment_pod(name, image)
            successes += int(ok)
            outputs.append(f"{name}: {'Created' if ok else 'Failed'}\n{message}")

    elif kind == "Suspicious pod churn":
        for i in range(pod_count):
            name = experiment_name(f"churn-{i + 1}")
            ok, message = create_experiment_pod(
                name, image, ["sh", "-c", f"sleep {duration}"]
            )
            successes += int(ok)
            outputs.append(f"{name}: {'Created' if ok else 'Failed'}\n{message}")
            if ok:
                time.sleep(interval)
                deleted, delete_message = delete_experiment_pod(name)
                outputs.append(f"Delete {name}: {'Requested' if deleted else 'Failed'}\n{delete_message}")

    elif kind == "Invalid image pull":
        for i in range(pod_count):
            name = experiment_name(f"invalid-{i + 1}")
            test_image = image or f"invalid-image-does-not-exist-{i + 1}:latest"
            ok, message = create_experiment_pod(name, test_image)
            successes += int(ok)
            outputs.append(f"{name} ({test_image}): {'Created' if ok else 'Failed'}\n{message}")

    elif kind == "Orphan image pull":
        name = experiment_name("orphan")
        ok, message = create_experiment_pod(name, image)
        successes += int(ok)
        outputs.append(f"{name}: {'Created' if ok else 'Failed'}\n{message}")
        if ok:
            time.sleep(1)
            deleted, delete_message = delete_experiment_pod(name)
            outputs.append(f"Delete {name}: {'Requested' if deleted else 'Failed'}\n{delete_message}")
        outputs.append("Note: orphan-pull detection is timing-dependent.")

    elif kind == "Pod creation burst":
        for i in range(pod_count):
            name = experiment_name(f"burst-{i + 1}")
            ok, message = create_experiment_pod(
                name, image, ["sh", "-c", f"sleep {duration}"]
            )
            successes += int(ok)
            outputs.append(f"{name}: {'Created' if ok else 'Failed'}\n{message}")
            if i < pod_count - 1:
                time.sleep(interval)

    elif kind == "Different container images":
        images = [item.strip() for item in image.split(",") if item.strip()]
        if not images:
            return ["Enter at least one image name."], 0
        for item in images[:pod_count]:
            name = experiment_name("multi-image")
            ok, message = create_experiment_pod(name, item)
            successes += int(ok)
            outputs.append(f"{name} ({item}): {'Created' if ok else 'Failed'}\n{message}")

    elif kind == "CPU and memory pressure":
        name = experiment_name("resource-test")
        args = [
            "run", name, "--image=polinux/stress", "--restart=Never",
            f"--labels={EXPERIMENT_SELECTOR},experiment=resource-test",
            "-n", NAMESPACE, "--requests=cpu=100m,memory=64Mi",
            "--limits=cpu=500m,memory=256Mi", "--",
            "stress", "--cpu", str(cpu_count), "--vm", "1",
            "--vm-bytes", memory_size, "--timeout", f"{duration}s",
        ]
        ok, message = kubectl_run(args)
        successes += int(ok)
        outputs.append(f"{name}: {'Created' if ok else 'Failed'}\n{message}")

    elif kind == "Recovery observation":
        ok, message = kubectl_run(["get", "pods", "-n", NAMESPACE, "-o", "wide"])
        outputs.append("Current Pods:\n" + message)
        outputs.append(
            "No new Pods were created. Stop other test workloads and allow the "
            "configured quiet/stability period to pass, then check the policy state."
        )
        successes = int(ok)

    elif kind == "Large-scale pod deletion":
        ok, message = kubectl_run([
            "delete", "pods", "-n", NAMESPACE, "-l", EXPERIMENT_SELECTOR,
            "--wait=false",
        ])
        successes = int(ok)
        outputs.append(message)

    elif kind == "Mixed attack":
        for i in range(max(1, pod_count // 2)):
            name = experiment_name(f"mixed-invalid-{i + 1}")
            ok, message = create_experiment_pod(
                name, f"missing-mixed-image-{i + 1}:latest"
            )
            successes += int(ok)
            outputs.append(f"{name}: {'Created' if ok else 'Failed'}\n{message}")
        for i in range(max(1, pod_count - pod_count // 2)):
            name = experiment_name(f"mixed-burst-{i + 1}")
            ok, message = create_experiment_pod(
                name, image, ["sh", "-c", f"sleep {duration}"]
            )
            successes += int(ok)
            outputs.append(f"{name}: {'Created' if ok else 'Failed'}\n{message}")
            if ok:
                time.sleep(interval)
                deleted, delete_message = delete_experiment_pod(name)
                outputs.append(f"Delete {name}: {'Requested' if deleted else 'Failed'}\n{delete_message}")

    return outputs, successes


def render_experiment_page():
    show_page_title(
        "Experiment Center",
        "Launch controlled image-pull and pod-activity tests from this dashboard."
    )

    # Confirm the cluster connection before allowing a workload to be launched.
    # connected, connection_message = kubectl_run(
    #     ["get", "namespace", NAMESPACE, "-o", "name"], timeout=10
    # )
    # status_col, namespace_col = st.columns([1, 2])
    # with status_col:
    #     st.metric("Cluster connection", "Connected" if connected else "Unavailable")
    # with namespace_col:
    #     st.metric("Target namespace", NAMESPACE)

    # if not connected:
    #     st.error(connection_message)
    #     st.info("Start Kubernetes and make sure the current user can access the cluster with kubectl.")
    #     return

    st.subheader("Run an experiment")
    experiment_options = [
        "Normal workload",
        "Suspicious pod churn",
        "Invalid image pull",
        "Orphan image pull",
        "Pod creation burst",
        "Different container images",
        "CPU and memory pressure",
        "Recovery observation",
        "Large-scale pod deletion",
        "Mixed attack",
    ]
    selected = st.selectbox("Experiment type", experiment_options)
    if selected == "Large-scale pod deletion":
        st.warning("This deletes only Pods labelled as experiment Pods in the selected namespace.")
        confirm_delete = st.checkbox("I understand and want to delete experiment Pods.")

    with st.form("experiment_configuration"):
        left, right = st.columns(2)
        with left:
            if selected == "Different container images":
                image_value = st.text_input(
                    "Container images (comma-separated)",
                    value="nginx:latest, redis:latest, busybox:latest, debian:bookworm-slim",
                    help="One Pod will be created for each image, up to the Pod count.",
                )
            else:
                default_image = "busybox:latest"
                if selected in {"Normal workload", "Orphan image pull"}:
                    default_image = "nginx:latest"
                elif selected == "Invalid image pull":
                    default_image = "nonexistent-image:latest"
                image_value = st.text_input(
                    "Container image",
                    value=default_image,
                    help="Image used by this experiment. For the invalid-image test, enter an image name that does not exist.",
                )
            pod_count = st.number_input(
                "Number of Pods", min_value=1, max_value=30, value=3, step=1,
                disabled=selected in {"Orphan image pull", "CPU and memory pressure", "Recovery observation", "Large-scale pod deletion"},
            )
        with right:
            interval = st.number_input(
                "Delay between actions (seconds)", min_value=0.0, max_value=10.0,
                value=1.0, step=0.5,
                disabled=selected in {"Normal workload", "Invalid image pull", "Orphan image pull", "Different container images", "CPU and memory pressure", "Recovery observation", "Large-scale pod deletion"},
            )
            duration = st.number_input(
                "Workload duration (seconds)", min_value=10, max_value=600,
                value=60, step=10,
                disabled=selected not in {"Suspicious pod churn", "Pod creation burst", "CPU and memory pressure", "Mixed attack"},
            )
            cpu_count = st.number_input(
                "CPU workers", min_value=1, max_value=4, value=1,
                disabled=selected != "CPU and memory pressure",
            )
            memory_size = st.selectbox(
                "Memory workload", ["64M", "100M", "200M", "400M"],
                index=1, disabled=selected != "CPU and memory pressure",
            )

        submitted = st.form_submit_button(
            "Run experiment", type="primary", use_container_width=True
        )

    if submitted:
        if selected == "Large-scale pod deletion" and not confirm_delete:
            st.info("Confirm the deletion checkbox before submitting.")
            return
        with st.spinner(f"Running {selected.lower()}..."):
            outputs, successes = execute_experiment(
                selected, image_value.strip(), int(pod_count),
                float(interval), int(duration), int(cpu_count), memory_size,
            )
        if successes:
            st.success(f"Experiment submitted. Successful operations: {successes}")
        elif selected not in {"Recovery observation"}:
            st.warning("The experiment did not report any successful Pod creation.")
        with st.expander("Execution details", expanded=True):
            for output in outputs:
                st.code(output, language="text")
        st.caption("The detector may take a short time to record events and update the policy state.")

    st.divider()
    st.subheader("Experiment Pods")
    action_col, cleanup_col = st.columns([1, 1])
    with action_col:
        if st.button("Refresh Pod list", use_container_width=True):
            st.rerun()
    with cleanup_col:
        if st.button("Clean up experiment Pods", type="secondary", use_container_width=True):
            ok, message = kubectl_run([
                "delete", "pods", "-n", NAMESPACE, "-l", EXPERIMENT_SELECTOR,
                "--wait=false",
            ])
            if ok:
                st.success("Cleanup request submitted.")
            else:
                st.error(message)

    ok, pod_output = kubectl_run([
        "get", "pods", "-n", NAMESPACE, "-l", EXPERIMENT_SELECTOR, "-o", "wide"
    ])
    if ok:
        st.code(pod_output or "No experiment Pods found.", language="text")
    else:
        st.warning(pod_output)

    with st.expander("Inspect a Pod"):
        pod_name = st.text_input("Pod name", placeholder="Enter an experiment Pod name")
        if st.button("Describe Pod"):
            if pod_name.strip():
                ok, details = kubectl_run([
                    "describe", "pod", pod_name.strip(), "-n", NAMESPACE
                ])
                st.code(details, language="text")
            else:
                st.warning("Enter a Pod name first.")



# ------------------------------------------------------------
# Header
# ------------------------------------------------------------

show_page_title(
    "Kubernetes Image Pull DOS Attack Detector and Mitigation",
    f"Namespace: {NAMESPACE}  ·  Updated {datetime.now().strftime('%H:%M:%S')}"
)

if cluster_error:
    st.warning(cluster_error)


# ------------------------------------------------------------
# Overview: resource status, summary and recent events
# ------------------------------------------------------------


active_pods = sum(
    1 for pod in pods
    if pod["Status"] in {"Running", "Pending"}
)

quota_text = (
    f'{quota["used_pods"]} / {quota["hard_pods"]}'
    if quota else "—"
)

cards = st.columns(4)

with cards[0]:
    st.markdown(
        metric_card(
            "POLICY STATE",
            policy_state.replace("_", " "),
            "Adaptive policy",
            status_color(policy_state),
        ),
        unsafe_allow_html=True,
    )

with cards[1]:
    st.markdown(
        metric_card(
            "TOTAL PODS",
            len(pods),
            f"{active_pods} running or pending",
            COLORS["ACCENT"],
        ),
        unsafe_allow_html=True,
    )

with cards[2]:
    st.markdown(
        metric_card(
            "POD QUOTA",
            quota_text,
            "Used / hard limit",
            COLORS["ORPHAN_PULL"],
        ),
        unsafe_allow_html=True,
    )

with cards[3]:
    st.markdown(
        metric_card(
            f"EVENTS / {DETECTION_WINDOW_SECONDS}s",
            current_churn,
            "Recent namespace events",
            COLORS["SUSPICIOUS"],
        ),
        unsafe_allow_html=True,
    )

st.markdown("---")
section_title("Node Resource Monitoring")

if resource_metrics:
    for metric in resource_metrics:
        st.markdown(f"**{metric['Node']}**")

        cpu_percent = metric["CPU Percent"]
        memory_percent = metric["Memory Percent"]

        cpu_col, memory_col = st.columns(2)

        with cpu_col:
            st.metric(
                "CPU utilization",
                f"{cpu_percent:.1f}%",
                metric["CPU Usage"],
            )
            st.progress(
                min(cpu_percent / 100, 1.0),
                text=f"High threshold: {CPU_THRESHOLD}%",
            )

            if cpu_percent >= CPU_THRESHOLD:
                st.error("High CPU utilization")
            else:
                st.success("CPU normal")

        with memory_col:
            st.metric(
                "Memory utilization",
                f"{memory_percent:.1f}%",
                metric["Memory Usage"],
            )
            st.progress(
                min(memory_percent / 100, 1.0),
                text=f"High threshold: {MEMORY_THRESHOLD}%",
            )

            if memory_percent >= MEMORY_THRESHOLD:
                st.error("High memory utilization")
            else:
                st.success("Memory normal")

else:
    st.info(metrics_error or "Node metrics are unavailable.")

st.markdown("---")
section_title("Event Activity")

chart_col, severity_col = st.columns([1.4, 1])

with chart_col:
    if not events.empty:
        chart_df = events.copy()
        chart_df["Minute"] = chart_df["timestamp"].dt.floor("min")
        chart_df = (
            chart_df.groupby(
                ["Minute", "severity"],
                dropna=False
            )
            .size()
            .reset_index(name="Events")
        )
        chart_df = chart_df[
            chart_df["Minute"] >= now_utc - pd.Timedelta(hours=1)
        ]

        if not chart_df.empty:
            fig = px.bar(
                chart_df,
                x="Minute",
                y="Events",
                color="severity",
                barmode="stack",
                color_discrete_map=COLORS,
                labels={
                    "Minute": "Time (UTC)",
                    "severity": "Severity",
                },
            )
            fig.update_layout(
                paper_bgcolor="#FFFFFF",
                plot_bgcolor="#FFFFFF",
                font_color=COLORS["TEXT"],
                margin=dict(l=10, r=10, t=15, b=10),
                legend_title_text="Severity",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events in the last hour.")
    else:
        st.info("No detector events recorded yet.")

with severity_col:
    if (
        not events.empty
        and events["severity"].str.strip().ne("").any()
    ):
        severity_df = (
            events["severity"]
            .replace("", "UNKNOWN")
            .value_counts()
            .rename_axis("Severity")
            .reset_index(name="Events")
        )

        fig = px.pie(
            severity_df,
            names="Severity",
            values="Events",
            hole=0.58,
            color="Severity",
            color_discrete_map=COLORS,
        )
        fig.update_layout(
            paper_bgcolor="#FFFFFF",
            font_color=COLORS["TEXT"],
            margin=dict(l=5, r=5, t=15, b=5),
            legend_title_text="",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Severity distribution will appear when events are recorded.")

st.markdown("---")
section_title("Recent Detector Events")

if not events.empty:
    recent = events.head(12).copy()
    recent["Timestamp"] = recent["timestamp"].apply(format_time)

    recent = recent.rename(columns={
        "pod": "Pod",
        "event_type": "Event",
        "reason": "Reason",
        "churn_60s": "Churn",
        "severity": "Severity",
        "details": "Details",
    })

    visible_columns = [
        "Timestamp",
        "Pod",
        "Event",
        "Reason",
        "Churn",
        "Severity",
        "Details",
    ]

    st.dataframe(
        recent[visible_columns],
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("Filter and export events"):
        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:
            severity_options = sorted(
                value for value in events["severity"].unique()
                if value.strip()
            )
            selected_severities = st.multiselect(
                "Severity",
                severity_options,
                default=severity_options,
            )

        with filter_col2:
            event_options = sorted(
                value for value in events["event_type"].unique()
                if value.strip()
            )
            selected_events = st.multiselect(
                "Event type",
                event_options,
                default=event_options,
            )

        filtered = events.copy()
        filtered = filtered[
            filtered["severity"].isin(selected_severities)
            & filtered["event_type"].isin(selected_events)
        ]

        search_value = st.text_input(
            "Search Pod, reason or details"
        )

        if search_value.strip():
            mask = filtered[
                ["pod", "reason", "details"]
            ].astype(str).apply(
                lambda column: column.str.contains(
                    search_value,
                    case=False,
                    na=False,
                )
            ).any(axis=1)
            filtered = filtered[mask]

        st.caption(f"{len(filtered)} matching events")

        st.download_button(
            "Download filtered events",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="filtered_detector_events.csv",
            mime="text/csv",
        )

else:
    st.info("No events to display.")

if policy_state in {
    "PULL_FLOOD",
    "ORPHAN_PULL",
    "RESOURCE_PRESSURE",
}:
    st.error(f"Active policy state: {policy_state.replace('_', ' ')}")
elif policy_state == "SUSPICIOUS":
    st.warning("Suspicious activity reported by the policy engine.")
elif policy_state == "RECOVERY":
    st.info("Recovery monitoring is in progress.")
elif policy_state == "NORMAL":
    st.success("System state is normal.")
else:
    st.warning("Policy state is unavailable or unrecognized.")


# ------------------------------------------------------------
# ------------------------------------------------------------
# Experiments
# ------------------------------------------------------------

render_experiment_page()


# Pods
# ------------------------------------------------------------

with st.expander("Pod details", expanded=False):

    section_title("Pods")

    if pods:
        pod_df = pd.DataFrame(pods)

        status_options = sorted(
            pod_df["Status"].dropna().unique().tolist()
        )

        selected_statuses = st.multiselect(
            "Filter by status",
            status_options,
            default=status_options,
        )

        shown = pod_df[
            pod_df["Status"].isin(selected_statuses)
        ].copy()

        shown["Created"] = shown["Created"].apply(format_time)

        st.caption(f"{len(shown)} of {len(pod_df)} Pods")

        st.dataframe(
            shown,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download Pods CSV",
            data=shown.to_csv(index=False).encode("utf-8"),
            file_name="current_pods.csv",
            mime="text/csv",
        )

    else:
        st.info("No Pods found or the Kubernetes API is unavailable.")


    # ------------------------------------------------------------
# Resource Quotas
# ------------------------------------------------------------

with st.expander("Resource quota details", expanded=False):

    section_title("Resource Quota")

    if quota:
        q1, q2, q3 = st.columns(3)

        with q1:
            st.markdown(
                metric_card(
                    "QUOTA",
                    quota["name"],
                    "Kubernetes ResourceQuota",
                    COLORS["ACCENT"],
                ),
                unsafe_allow_html=True,
            )

        with q2:
            st.markdown(
                metric_card(
                    "PODS USED",
                    quota["used_pods"],
                    "Current usage",
                    COLORS["NORMAL"],
                ),
                unsafe_allow_html=True,
            )

        with q3:
            st.markdown(
                metric_card(
                    "POD LIMIT",
                    quota["hard_pods"],
                    "Hard limit",
                    COLORS["ORPHAN_PULL"],
                ),
                unsafe_allow_html=True,
            )

        ratio = (
            min(quota["used_pods"] / quota["hard_pods"], 1.0)
            if quota["hard_pods"] > 0
            else 0
        )

        st.progress(
            ratio,
            text=f'{quota["used_pods"]} / {quota["hard_pods"]} Pods used',
        )

        section_title("Quota Details")

        keys = sorted(
            set(quota["hard"].keys()) | set(quota["used"].keys())
        )

        detail_df = pd.DataFrame([
            {
                "Resource": key,
                "Used": quota["used"].get(key, "—"),
                "Hard limit": quota["hard"].get(key, "—"),
            }
            for key in keys
        ])

        st.dataframe(
            detail_df,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.warning(
            f"ResourceQuota '{QUOTA_NAME}' is unavailable in '{NAMESPACE}'."
        )


    # ------------------------------------------------------------
# Footer
# ------------------------------------------------------------

st.markdown("---")
st.caption("Image Pull Defense · Live monitoring and experiment controls · Refresh: 5 seconds")
