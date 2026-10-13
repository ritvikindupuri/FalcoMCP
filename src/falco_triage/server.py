"""Falco-Triage Model Context Protocol (MCP) Server.

Connects AI assistants to live Falcosidekick alert streams and live Kubernetes
clusters for real-time alert triage, workload correlation, and CNCF Falco
structured exception generation. Supports both:
  - Path 1: Live Cluster Triage & Rule Tuning
  - Path 2: Zero-to-One Lab & Sandbox Bootstrap (Automated Falco & Sample Workload Provisioning)
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional
from mcp.server.mcpserver import MCPServer
from ruamel.yaml import YAML

from falco_triage.falco_client import FalcoClient, FalcoEvent
from falco_triage.k8s_client import K8sClient
from falco_triage.exception_engine import FalcoExceptionEngine
from falco_triage.rule_validator import FalcoRuleValidator
from falco_triage.lab_bootstrap import LabBootstrapper

# Initialize MCP Server
app = MCPServer(
    name="falco-triage-mcp",
    version="0.1.0",
    description="Container Security & Falco Rule Tuning MCP Server",
)

exception_engine = FalcoExceptionEngine()
rule_validator = FalcoRuleValidator()


# ============================================================================
# MCP TOOLS
# ============================================================================

@app.tool()
async def check_lab_environment(
    falcosidekick_daemon_url: str = "http://localhost:2801",
    falcosidekick_ui_url: str = "http://localhost:2802",
) -> Dict[str, Any]:
    """Check the live status of Docker, Kubernetes, and Falcosidekick endpoints.
    
    Returns connection and health status for each subsystem.
    """
    valid_daemon_url = _validate_url(falcosidekick_daemon_url)
    valid_ui_url = _validate_url(falcosidekick_ui_url)
    docker_status = LabBootstrapper.check_docker_running()
    k8s = K8sClient()
    k8s_status = k8s.check_connection()

    falco = FalcoClient(daemon_url=valid_daemon_url, ui_url=valid_ui_url)
    daemon_health = await falco.check_daemon_health()
    ui_health = await falco.check_ui_health()

    return {
        "docker": docker_status,
        "kubernetes": k8s_status,
        "falcosidekick_daemon": daemon_health,
        "falcosidekick_ui": ui_health,
        "ready_for_live_triage": k8s_status.get("connected", False) or daemon_health.get("reachable", False),
    }


@app.tool()
async def bootstrap_falcosidekick_lab(
    daemon_port: int = 2801,
    ui_port: int = 2802,
) -> Dict[str, Any]:
    """[Path 2] Spin up fresh Falcosidekick and Falcosidekick-UI containers in Docker.
    
    If Docker Desktop is stopped, attempts to launch it. Once Docker is ready,
    deploys official falcosecurity/falcosidekick and falcosidekick-ui containers.
    """
    docker_status = LabBootstrapper.check_docker_running()
    if not docker_status.get("running"):
        start_result = LabBootstrapper.start_docker_desktop()
        return {
            "status": "waiting_for_docker",
            "message": "Docker engine was not running. Launch command was dispatched to Docker Desktop.",
            "details": start_result,
            "next_step": "Wait ~30 seconds for Docker Desktop to finish booting, then re-run this tool.",
        }

    return LabBootstrapper.launch_falcosidekick_containers(daemon_port=daemon_port, ui_port=ui_port)


@app.tool()
def bootstrap_kind_cluster(
    cluster_name: str = "falco-lab",
    recreate: bool = False,
) -> Dict[str, Any]:
    """[Path 2] Create a fresh local Kubernetes cluster using Kind for testing Falco rules.
    
    Requires Docker to be running. Automatically checks for Kind CLI.
    """
    return LabBootstrapper.bootstrap_kind_cluster(cluster_name=cluster_name, recreate=recreate)


@app.tool()
def deploy_falcosidekick_to_kubernetes() -> Dict[str, Any]:
    """[Path 2] Deploy official Falcosidekick and UI manifests directly into the active Kubernetes cluster."""
    return LabBootstrapper.deploy_falcosidekick_to_kubernetes()


@app.tool()
def deploy_sample_k8s_workloads() -> Dict[str, Any]:
    """[Path 2] Deploy sample Kubernetes test pods (Nginx web-frontend & Prometheus node-exporter) to test triage and exceptions."""
    return LabBootstrapper.deploy_sample_workloads()


@app.tool()
def install_falco_to_kubernetes() -> Dict[str, Any]:
    """[Path 2] Automatically install full Falco with Falcosidekick into Kubernetes via Helm or native manifests."""
    return LabBootstrapper.install_falco_to_cluster()


@app.tool()
async def dispatch_test_falco_alert(
    template_name: str = "shell_in_container",
    daemon_url: str = "http://localhost:2801",
    k8s_ns: Optional[str] = None,
    k8s_pod: Optional[str] = None,
    proc_name: Optional[str] = None,
    container_image: Optional[str] = None,
) -> Dict[str, Any]:
    """[Path 2] Dispatch a real-world Falco event payload to the live Falcosidekick daemon.
    
    Supported templates:
      - 'shell_in_container': Terminal shell spawned inside container
      - 'write_below_etc': Unauthorized file write under /etc (e.g. node-exporter)
      - 'read_sensitive_file': Sensitive credential file read (e.g. datadog-agent)
    """
    overrides: Dict[str, Any] = {"output_fields": {}}
    if k8s_ns:
        overrides["output_fields"]["k8s.ns.name"] = k8s_ns
    if k8s_pod:
        overrides["output_fields"]["k8s.pod.name"] = k8s_pod
    if proc_name:
        overrides["output_fields"]["proc.name"] = proc_name
    if container_image:
        overrides["output_fields"]["container.image.repository"] = container_image.split(":")[0]
        overrides["output_fields"]["container.image"] = container_image

    if not overrides["output_fields"]:
        overrides = None

    valid_daemon_url = _validate_url(daemon_url)
    return await LabBootstrapper.dispatch_real_sample_event(
        daemon_url=valid_daemon_url,
        template_name=template_name,
        overrides=overrides,
    )


@app.tool()
async def ingest_falco_alerts(
    source: str = "falcosidekick",
    falcosidekick_ui_url: str = "http://localhost:2802",
    file_path: Optional[str] = None,
    rule_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """[Path 1] Ingest live Falco alerts from Falcosidekick UI API or local JSON log files.
    
    Clusters alerts by rule, severity, affected pods, and processes to pinpoint
    sources of false positives and alert fatigue.
    """
    events: List[FalcoEvent] = []

    if source == "file":
        if not file_path:
            raise ValueError("file_path parameter is required when source='file'.")
        safe_log_path = _validate_safe_path(file_path, ALLOWED_LOG_EXTENSIONS)
        if not os.path.exists(safe_log_path):
            raise ValueError(f"File path '{safe_log_path}' does not exist.")
        events = FalcoClient.load_events_from_json_file(safe_log_path)
    else:
        validated_ui_url = _validate_url(falcosidekick_ui_url)
        client = FalcoClient(ui_url=validated_ui_url)
        events = await client.query_ui_events(
            rule=rule_filter,
            priority=priority_filter,
            limit=limit,
        )

    if rule_filter:
        events = [e for e in events if rule_filter.lower() in e.rule.lower()]
    if priority_filter:
        events = [e for e in events if priority_filter.lower() in e.priority.lower()]

    clusters = FalcoClient.cluster_alerts(events)

    clusters_summary = []
    for c in clusters:
        clusters_summary.append({
            "rule": c.rule,
            "priority": c.priority,
            "count": c.count,
            "first_seen": c.first_seen,
            "last_seen": c.last_seen,
            "namespaces": c.namespaces,
            "pods": c.pods[:5],
            "processes": c.processes,
            "container_images": c.container_images,
            "sample_outputs": c.sample_outputs[:2],
            "sample_output_fields": c.raw_output_fields_samples[:2],
        })

    return {
        "total_events_ingested": len(events),
        "total_clusters": len(clusters),
        "top_clusters": clusters_summary[:10],
    }


@app.tool()
def correlate_k8s_workload(
    namespace: str,
    pod_name: str,
    kubeconfig_path: Optional[str] = None,
    context_name: Optional[str] = None,
) -> Dict[str, Any]:
    """[Path 1] Query the active Kubernetes cluster to inspect the Pod flagged in a Falco alert.
    
    Retrieves container specs, securityContext (privileged, capabilities, read-only FS),
    hostPath volume mounts, owner controllers (Deployment/DaemonSet), and labels.
    """
    client = K8sClient(kubeconfig_path=kubeconfig_path, context_name=context_name)
    return client.inspect_pod(namespace=namespace, pod_name=pod_name)


@app.tool()
def generate_falco_exception(
    rule_name: str,
    output_fields_samples: List[Dict[str, Any]],
    strategy: str = "least_privilege",
    exception_name: Optional[str] = None,
) -> Dict[str, Any]:
    """[Path 1 & 2] Synthesize a CNCF Falco 0.35+ structured rule exception from alert output_fields.
    
    Strategies:
      - 'least_privilege' (Recommended): Scopes by [k8s.ns.name, proc.name, container.image.repository]
                                         plus fd.name if file activity detected.
      - 'namespace_process': Scopes by [k8s.ns.name, proc.name].
      - 'container_process': Scopes by [container.image.repository, proc.name].
      - 'process_only': Scopes by proc.name only.
    
    Returns structured exception object and ready-to-use YAML string.
    """
    exc_dict = exception_engine.synthesize_from_output_fields(
        rule_name=rule_name,
        output_fields_samples=output_fields_samples,
        strategy=strategy,
        exception_name=exception_name,
    )
    yaml_str = exception_engine.to_yaml_string(exc_dict)
    val_report = rule_validator.validate_rule_yaml(yaml_str)

    return {
        "rule_name": rule_name,
        "strategy": strategy,
        "exception_structure": exc_dict,
        "yaml_content": yaml_str,
        "validation": val_report,
    }


import re
from urllib.parse import urlparse

# Security hardening: Disallow file path traversal outside safe extensions
ALLOWED_RULE_EXTENSIONS = {".yaml", ".yml", ".json"}
ALLOWED_LOG_EXTENSIONS = {".json", ".jsonl", ".log", ".txt"}


def _validate_safe_path(file_path: str, allowed_extensions: set[str]) -> str:
    """Harden file path handling against traversal and unauthorized file extension tampering."""
    if not file_path:
        raise ValueError("File path cannot be empty.")
    norm_path = os.path.abspath(os.path.expanduser(file_path))
    _, ext = os.path.splitext(norm_path)
    if ext.lower() not in allowed_extensions:
        raise ValueError(
            f"Security Error: Prohibited file extension '{ext}'. "
            f"Must be one of: {sorted(list(allowed_extensions))}"
        )
    return norm_path


def _validate_url(url: str) -> str:
    """Harden URL parameters against arbitrary SSRF exfiltration schemes."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Security Error: Invalid URL scheme '{parsed.scheme}'. Only http and https allowed.")
    if not parsed.netloc:
        raise ValueError("Security Error: Invalid URL format; host must be specified.")
    return url


@app.tool()
def append_falco_exception_to_file(
    file_path: str,
    exception_yaml: str,
) -> Dict[str, Any]:
    """[Path 1 & 2] Append or merge a structured exception into a local falco_rules.local.yaml file.
    
    Preserves existing rules and YAML formatting, merging values if the exception
    already exists. Enforces strict extension validation (.yaml, .yml, .json).
    """
    safe_path = _validate_safe_path(file_path, ALLOWED_RULE_EXTENSIONS)
    yaml_parser = YAML()
    parsed = yaml_parser.load(exception_yaml)
    if isinstance(parsed, list):
        rule_dict = parsed[0]
    elif isinstance(parsed, dict):
        rule_dict = parsed
    else:
        raise ValueError("Invalid exception YAML format.")

    result = exception_engine.append_to_file(file_path=safe_path, new_exception=rule_dict)
    result["command_executed"] = f"append_falco_exception_to_file(file_path='{safe_path}')"
    result["requires_human_approval"] = True
    result["approval_options"] = ["Allow", "Deny", "Always"]
    result["dropdown_display"] = {
        "summary": f"Exception write result for {safe_path} (Click to expand)",
        "output": json.dumps(result, indent=2),
    }
    return result


@app.tool()
def validate_falco_rule(
    yaml_content: str,
) -> Dict[str, Any]:
    """[Path 1 & 2] Validate Falco YAML rules or exceptions against official filtercheck fields and schema.
    
    Checks field names (proc.*, fd.*, k8s.*, container.*), comparison operators,
    tuple length alignment, and base rule required attributes.
    """
    return rule_validator.validate_rule_yaml(yaml_content)


@app.tool()
def generate_pod_isolation_policy(
    namespace: str,
    pod_name: str,
    allow_dns: bool = True,
    kubeconfig_path: Optional[str] = None,
) -> Dict[str, Any]:
    """[Path 1] Generate a production Kubernetes NetworkPolicy manifest to isolate a compromised pod.
    
    Denies all ingress and egress traffic except DNS (port 53 UDP/TCP).
    """
    client = K8sClient(kubeconfig_path=kubeconfig_path)
    res = client.generate_isolation_network_policy(
        namespace=namespace,
        pod_name=pod_name,
        allow_dns=allow_dns,
    )
    res["command_executed"] = res.get("remediation_command", f"kubectl apply -n {namespace} -f <networkpolicy.yaml>")
    res["requires_human_approval"] = True
    res["approval_options"] = ["Allow", "Deny", "Always"]
    res["dropdown_display"] = {
        "summary": f"NetworkPolicy YAML for {namespace}/{pod_name} (Click to expand)",
        "output": res.get("yaml", ""),
    }
    return res


# ============================================================================
# MCP PROMPTS: PATH 1 (LIVE OPS) vs PATH 2 (BOOTSTRAP SANDBOX)
# ============================================================================

@app.prompt(
    name="path1_live_cluster_triage",
    description="Path 1: Ingest live alerts from an existing Falco & Kubernetes deployment and tune noisy rules."
)
def prompt_path1_live_cluster_triage(
    falcosidekick_ui_url: str = "http://localhost:2802",
) -> List[Dict[str, Any]]:
    return [
        {
            "role": "user",
            "content": (
                f"I have an active Falco and Kubernetes deployment. "
                f"Please run `ingest_falco_alerts` against '{falcosidekick_ui_url}' to pull recent alerts. "
                f"Identify the highest-volume noisy rules, correlate the affected pods using `correlate_k8s_workload`, "
                f"and generate least-privilege Falco structured exceptions with `generate_falco_exception`."
            ),
        }
    ]


@app.prompt(
    name="path2_bootstrap_sandbox_lab",
    description="Path 2: Set up a sandbox testing environment (create fresh Kind cluster or containers, deploy Falcosidekick, and test alerts with pre-installed Falco)."
)
def prompt_path2_bootstrap_sandbox_lab(
    create_k8s_cluster: bool = False,
) -> List[Dict[str, Any]]:
    k8s_instruction = (
        "create a fresh Kind cluster using `bootstrap_kind_cluster`, deploy Falcosidekick with `deploy_falcosidekick_to_kubernetes`, and deploy sample pods with `deploy_sample_k8s_workloads`"
        if create_k8s_cluster
        else "spin up fresh Falcosidekick and UI containers using `bootstrap_falcosidekick_lab`"
    )
    return [
        {
            "role": "user",
            "content": (
                f"I need a fresh testing environment. Please check prerequisites with `check_lab_environment`. "
                f"Falco is installed per prerequisite instructions. Then {k8s_instruction}. Once ready, dispatch a test alert with `dispatch_test_falco_alert` "
                f"and walk me through tuning it."
            ),
        }
    ]


@app.prompt(
    name="spin_up_sample_cluster_and_workloads",
    description="Path 2: Setup sample workloads and Falcosidekick event forwarders when Falco and Docker/K8s are pre-installed."
)
def prompt_spin_up_sample_cluster_and_workloads() -> List[Dict[str, Any]]:
    return [
        {
            "role": "user",
            "content": (
                "I have Docker, Kubernetes, and Falco installed per the prerequisites guide. "
                "Please run `check_lab_environment` to inspect my cluster, run `deploy_falcosidekick_to_kubernetes` "
                "to deploy Falcosidekick and the Web UI, run `deploy_sample_k8s_workloads` to spin up sample Nginx "
                "and node-exporter pods, and dispatch a test alert using `dispatch_test_falco_alert` so I can see live triage."
            ),
        }
    ]


@app.prompt(
    name="tune_noisy_rule",
    description="Path 1: Target and tune a specific noisy rule in an active cluster."
)
def prompt_tune_noisy_rule(rule_name: str) -> List[Dict[str, Any]]:
    return [
        {
            "role": "user",
            "content": (
                f"We are experiencing false positives from the rule '{rule_name}'. "
                f"Please search for recent occurrences using `ingest_falco_alerts` with rule_filter='{rule_name}', "
                f"inspect the offending processes and pods, and generate a precision exception in `falco_rules.local.yaml`."
            ),
        }
    ]


@app.prompt(
    name="isolate_compromised_pod",
    description="Path 1: Investigate and quarantine an actively compromised pod."
)
def prompt_isolate_compromised_pod(namespace: str, pod_name: str) -> List[Dict[str, Any]]:
    return [
        {
            "role": "user",
            "content": (
                f"Investigate pod '{pod_name}' in namespace '{namespace}' using `correlate_k8s_workload`. "
                f"Check for privilege escalation, host mounts, or suspicious process activity, "
                f"and generate an immediate isolation NetworkPolicy using `generate_pod_isolation_policy`."
            ),
        }
    ]


def main():
    """Main entrypoint for MCP Server stdio transport."""
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
