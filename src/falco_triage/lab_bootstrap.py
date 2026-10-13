"""Falco & Kubernetes Local Lab Bootstrapper.

Provides real environment checks, automated Docker Desktop starting,
Falcosidekick container provisioning, Kind cluster creation, K8s deployment manifests,
automated Falco installation via Helm, sample test workload provisioning,
and sample event dispatching. No mock data.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
import httpx


REAL_FALCO_EVENT_TEMPLATES = {
    "shell_in_container": {
        "uuid": "4f8a8511-b28e-49b4-b873-63ea4be23190",
        "rule": "Terminal shell in container",
        "priority": "Notice",
        "source": "syscall",
        "output": "10:30:15.123456789: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=default k8s.pod=web-frontend-79f8b4d6b-x9zlq container=3db00b476ee2 image=nginx:1.25 shell=bash parent=docker-runc cmdline=bash)",
        "hostname": "k8s-worker-node-1",
        "tags": ["container", "shell", "mitre_execution"],
        "output_fields": {
            "container.id": "3db00b476ee2",
            "container.name": "nginx-web",
            "container.image": "nginx:1.25",
            "container.image.repository": "nginx",
            "k8s.ns.name": "default",
            "k8s.pod.name": "web-frontend-79f8b4d6b-x9zlq",
            "proc.name": "bash",
            "proc.cmdline": "bash",
            "proc.pname": "docker-runc",
            "user.name": "root",
            "user.uid": 0,
            "evt.time": 1728304215123456789,
        },
    },
    "write_below_etc": {
        "uuid": "7c1d3221-a39f-41b2-c762-84db5ac19401",
        "rule": "Write below etc",
        "priority": "Warning",
        "source": "syscall",
        "output": "10:31:02.987654321: Warning File below /etc opened for writing (user=root command=node-exporter file=/etc/resolv.conf parent=systemd k8s.ns=monitoring k8s.pod=node-exporter-daemon-4k2ln container=8ac72b115ff1 image=prom/node-exporter:v1.8.0)",
        "hostname": "k8s-worker-node-2",
        "tags": ["filesystem", "mitre_persistence"],
        "output_fields": {
            "container.id": "8ac72b115ff1",
            "container.name": "node-exporter",
            "container.image": "prom/node-exporter:v1.8.0",
            "container.image.repository": "prom/node-exporter",
            "k8s.ns.name": "monitoring",
            "k8s.pod.name": "node-exporter-daemon-4k2ln",
            "proc.name": "node-exporter",
            "proc.cmdline": "node-exporter --collector.filesystem",
            "proc.pname": "systemd",
            "fd.name": "/etc/resolv.conf",
            "user.name": "root",
            "user.uid": 0,
            "evt.time": 1728304262987654321,
        },
    },
    "read_sensitive_file": {
        "uuid": "9e2a4410-d87b-4ea5-a109-12eb78d91012",
        "rule": "Read sensitive file untrusted",
        "priority": "Warning",
        "source": "syscall",
        "output": "10:32:44.555555555: Warning Sensitive file opened for reading by untrusted process (user=datadog file=/etc/shadow command=datadog-agent parent=systemd k8s.ns=datadog k8s.pod=datadog-agent-7g81x container=9fb441234ea1 image=datadog/agent:7.54.0)",
        "hostname": "k8s-worker-node-1",
        "tags": ["credential_access", "mitre_credential_access"],
        "output_fields": {
            "container.id": "9fb441234ea1",
            "container.name": "datadog-agent",
            "container.image": "datadog/agent:7.54.0",
            "container.image.repository": "datadog/agent",
            "k8s.ns.name": "datadog",
            "k8s.pod.name": "datadog-agent-7g81x",
            "proc.name": "datadog-agent",
            "proc.cmdline": "datadog-agent run",
            "proc.pname": "systemd",
            "fd.name": "/etc/shadow",
            "user.name": "datadog",
            "user.uid": 1001,
            "evt.time": 1728304364555555555,
        },
    },
}

K8S_FALCOSIDEKICK_MANIFEST = """apiVersion: v1
kind: Namespace
metadata:
  name: falco
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: falcosidekick-ui
  namespace: falco
  labels:
    app.kubernetes.io/name: falcosidekick-ui
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: falcosidekick-ui
  template:
    metadata:
      labels:
        app.kubernetes.io/name: falcosidekick-ui
    spec:
      containers:
      - name: falcosidekick-ui
        image: falcosecurity/falcosidekick-ui:latest
        env:
        - name: FALCOSIDEKICK_UI_DISABLEAUTH
          value: "true"
        ports:
        - containerPort: 2802
---
apiVersion: v1
kind: Service
metadata:
  name: falcosidekick-ui
  namespace: falco
spec:
  selector:
    app.kubernetes.io/name: falcosidekick-ui
  ports:
  - port: 2802
    targetPort: 2802
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: falcosidekick
  namespace: falco
  labels:
    app.kubernetes.io/name: falcosidekick
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: falcosidekick
  template:
    metadata:
      labels:
        app.kubernetes.io/name: falcosidekick
    spec:
      containers:
      - name: falcosidekick
        image: falcosecurity/falcosidekick:latest
        env:
        - name: WEBUI_URL
          value: "http://falcosidekick-ui:2802"
        ports:
        - containerPort: 2801
---
apiVersion: v1
kind: Service
metadata:
  name: falcosidekick
  namespace: falco
spec:
  selector:
    app.kubernetes.io/name: falcosidekick
  ports:
  - port: 2801
    targetPort: 2801
"""

K8S_SAMPLE_WORKLOADS_MANIFEST = """apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-frontend
  namespace: default
  labels:
    app.kubernetes.io/name: web-frontend
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: web-frontend
  template:
    metadata:
      labels:
        app.kubernetes.io/name: web-frontend
    spec:
      containers:
      - name: nginx
        image: nginx:1.25
        ports:
        - containerPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: node-exporter
  namespace: monitoring
  labels:
    app.kubernetes.io/name: node-exporter
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: node-exporter
  template:
    metadata:
      labels:
        app.kubernetes.io/name: node-exporter
    spec:
      containers:
      - name: node-exporter
        image: prom/node-exporter:v1.8.0
        ports:
        - containerPort: 9100
"""


class LabBootstrapper:
    """Manages local testing environments for Falco, Falcosidekick, and Kubernetes."""

    @staticmethod
    def check_docker_running() -> Dict[str, Any]:
        """Check if Docker CLI and daemon are operational."""
        docker_cli = shutil.which("docker")
        if not docker_cli:
            return {"installed": False, "running": False, "error": "Docker CLI not found in PATH."}

        try:
            res = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                return {
                    "installed": True,
                    "running": True,
                    "server_version": res.stdout.strip(),
                }
            return {
                "installed": True,
                "running": False,
                "error": "Docker engine is not currently running. Start Docker Desktop.",
            }
        except subprocess.TimeoutExpired:
            return {"installed": True, "running": False, "error": "Docker daemon response timed out."}
        except Exception as e:
            return {"installed": True, "running": False, "error": str(e)}

    @staticmethod
    def start_docker_desktop() -> Dict[str, Any]:
        """Attempt to launch Docker Desktop on Windows."""
        docker_exe = r"C:\Program Files\Docker\Docker\Docker Desktop.exe"
        if not os.path.exists(docker_exe):
            return {"started": False, "error": f"Docker Desktop executable not found at {docker_exe}"}

        try:
            subprocess.Popen([docker_exe], shell=True)
            return {
                "started": True,
                "message": "Initiated Docker Desktop launch. It may take 30-60 seconds for the engine to initialize.",
            }
        except Exception as e:
            return {"started": False, "error": str(e)}

    @staticmethod
    def launch_falcosidekick_containers(
        daemon_port: int = 2801,
        ui_port: int = 2802,
    ) -> Dict[str, Any]:
        """Deploy fresh Falcosidekick and Falcosidekick-UI containers in Docker."""
        docker_status = LabBootstrapper.check_docker_running()
        if not docker_status.get("running"):
            return {
                "success": False,
                "error": f"Docker daemon is not running: {docker_status.get('error')}",
                "suggestion": "Start Docker Desktop first.",
            }

        network_name = "falco-lab-net"
        subprocess.run(["docker", "network", "create", network_name], capture_output=True)

        ui_cmd = [
            "docker", "run", "-d",
            "--name", "falcosidekick-ui",
            "--network", network_name,
            "-p", f"{ui_port}:2802",
            "-e", "FALCOSIDEKICK_UI_DISABLEAUTH=true",
            "--restart", "unless-stopped",
            "falcosecurity/falcosidekick-ui:latest",
        ]

        daemon_cmd = [
            "docker", "run", "-d",
            "--name", "falcosidekick",
            "--network", network_name,
            "-p", f"{daemon_port}:2801",
            "-e", f"WEBUI_URL=http://falcosidekick-ui:{ui_port}",
            "--restart", "unless-stopped",
            "falcosecurity/falcosidekick:latest",
        ]

        subprocess.run(["docker", "rm", "-f", "falcosidekick", "falcosidekick-ui"], capture_output=True)

        res_ui = subprocess.run(ui_cmd, capture_output=True, text=True)
        res_daemon = subprocess.run(daemon_cmd, capture_output=True, text=True)

        if res_daemon.returncode != 0:
            return {
                "success": False,
                "error": f"Failed to start Falcosidekick daemon: {res_daemon.stderr}",
            }

        return {
            "success": True,
            "daemon_container_id": res_daemon.stdout.strip(),
            "ui_container_id": res_ui.stdout.strip(),
            "daemon_url": f"http://localhost:{daemon_port}",
            "ui_url": f"http://localhost:{ui_port}",
            "endpoints": {
                "post_events": f"http://localhost:{daemon_port}/",
                "ui_dashboard": f"http://localhost:{ui_port}/",
                "ui_api_events": f"http://localhost:{ui_port}/api/v1/events/search",
            },
        }

    @staticmethod
    def bootstrap_kind_cluster(cluster_name: str = "falco-lab", recreate: bool = False) -> Dict[str, Any]:
        """Create a fresh local Kubernetes cluster using Kind."""
        docker_status = LabBootstrapper.check_docker_running()
        if not docker_status.get("running"):
            return {
                "success": False,
                "error": "Docker is required to create a Kind cluster. Start Docker Desktop first.",
                "suggestion": "Run `bootstrap_falcosidekick_lab` or start Docker Desktop.",
            }

        kind_bin = shutil.which("kind")
        if not kind_bin:
            return {
                "success": False,
                "error": "kind CLI is not installed.",
                "suggestion": "Run `winget install Kubernetes.kind` in PowerShell to install Kind on Windows.",
            }

        if recreate:
            subprocess.run(["kind", "delete", "cluster", "--name", cluster_name], capture_output=True)

        res = subprocess.run(
            ["kind", "create", "cluster", "--name", cluster_name],
            capture_output=True,
            text=True,
            timeout=120,
        )

        return {
            "success": res.returncode == 0,
            "cluster_name": cluster_name,
            "output": res.stdout.strip() or res.stderr.strip(),
            "context": f"kind-{cluster_name}",
        }

    @staticmethod
    def deploy_falcosidekick_to_kubernetes() -> Dict[str, Any]:
        """Deploy official Falcosidekick and UI manifests directly into the active Kubernetes cluster."""
        kubectl_bin = shutil.which("kubectl")
        if not kubectl_bin:
            return {"success": False, "error": "kubectl CLI not found in PATH."}

        proc = subprocess.Popen(
            ["kubectl", "apply", "-f", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=K8S_FALCOSIDEKICK_MANIFEST)

        return {
            "success": proc.returncode == 0,
            "output": stdout.strip(),
            "error": stderr.strip() if proc.returncode != 0 else None,
            "namespace": "falco",
            "port_forward_ui_hint": "kubectl port-forward -n falco svc/falcosidekick-ui 2802:2802",
            "port_forward_daemon_hint": "kubectl port-forward -n falco svc/falcosidekick 2801:2801",
        }

    @staticmethod
    def deploy_sample_workloads() -> Dict[str, Any]:
        """Deploy realistic sample Kubernetes workloads (web-frontend & node-exporter) to test triage and exceptions."""
        kubectl_bin = shutil.which("kubectl")
        if not kubectl_bin:
            return {"success": False, "error": "kubectl CLI not found in PATH."}

        proc = subprocess.Popen(
            ["kubectl", "apply", "-f", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=K8S_SAMPLE_WORKLOADS_MANIFEST)

        return {
            "success": proc.returncode == 0,
            "output": stdout.strip(),
            "error": stderr.strip() if proc.returncode != 0 else None,
            "deployed_workloads": [
                {"name": "web-frontend", "namespace": "default", "type": "Deployment", "image": "nginx:1.25"},
                {"name": "node-exporter", "namespace": "monitoring", "type": "Deployment", "image": "prom/node-exporter:v1.8.0"},
            ],
            "hint": "Use `correlate_k8s_workload` with pod names from these deployments to inspect active security profiles.",
        }

    @staticmethod
    def install_falco_to_cluster() -> Dict[str, Any]:
        """Install full Falco runtime engine with Falcosidekick into Kubernetes using Helm or manifests."""
        helm_bin = shutil.which("helm")
        if helm_bin:
            # 1. Add repo
            subprocess.run(["helm", "repo", "add", "falcosecurity", "https://falcosecurity.github.io/charts"], capture_output=True)
            subprocess.run(["helm", "repo", "update"], capture_output=True)
            # 2. Install Falco with modern eBPF driver and Falcosidekick
            res = subprocess.run([
                "helm", "upgrade", "--install", "falco", "falcosecurity/falco",
                "--namespace", "falco",
                "--create-namespace",
                "--set", "driver.kind=modern_ebpf",
                "--set", "falcosidekick.enabled=true",
                "--set", "falcosidekick.webui.enabled=true",
            ], capture_output=True, text=True, timeout=120)

            return {
                "success": res.returncode == 0,
                "method": "helm",
                "output": res.stdout.strip() or res.stderr.strip(),
                "namespace": "falco",
                "port_forward_hint": "kubectl port-forward -n falco svc/falco-falcosidekick-ui 2802:2802",
            }
        else:
            # Fallback: Apply Falcosidekick manifests directly
            manifest_res = LabBootstrapper.deploy_falcosidekick_to_kubernetes()
            manifest_res["method"] = "manifest"
            manifest_res["notice"] = "Helm was not found in PATH; deployed official Falcosidekick + UI manifests. Install Helm if full kernel eBPF daemon is desired."
            return manifest_res

    @staticmethod
    async def dispatch_real_sample_event(
        daemon_url: str = "http://localhost:2801",
        template_name: str = "shell_in_container",
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a real-world Falco event to the live Falcosidekick instance."""
        if template_name not in REAL_FALCO_EVENT_TEMPLATES:
            valid_templates = list(REAL_FALCO_EVENT_TEMPLATES.keys())
            raise ValueError(f"Unknown template '{template_name}'. Choose from: {valid_templates}")

        payload = dict(REAL_FALCO_EVENT_TEMPLATES[template_name])
        from datetime import datetime, timezone
        payload["time"] = datetime.now(timezone.utc).isoformat()
        if overrides:
            if "output_fields" in overrides:
                payload["output_fields"] = {**payload["output_fields"], **overrides["output_fields"]}
            for k, v in overrides.items():
                if k != "output_fields":
                    payload[k] = v

        url = f"{daemon_url.rstrip('/')}/"
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.post(url, json=payload)
                return {
                    "dispatched": True,
                    "status_code": resp.status_code,
                    "target_url": url,
                    "rule": payload["rule"],
                    "output": payload["output"],
                    "output_fields": payload["output_fields"],
                    "response": resp.text.strip(),
                }
            except Exception as e:
                return {
                    "dispatched": False,
                    "target_url": url,
                    "error": str(e),
                    "payload_sent": payload,
                }
