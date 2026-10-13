"""Kubernetes Cluster Correlation Client.

Interfaces with the live Kubernetes API using the official client.
Retrieves real Pod specs, security contexts, container images, and
synthesizes isolation NetworkPolicies. No mock data.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException


class K8sClient:
    """Client for querying live Kubernetes cluster context."""

    def __init__(self, kubeconfig_path: Optional[str] = None, context_name: Optional[str] = None):
        self.kubeconfig_path = kubeconfig_path
        self.context_name = context_name
        self._initialized = False
        self._v1: Optional[client.CoreV1Api] = None
        self._apps_v1: Optional[client.AppsV1Api] = None
        self._networking_v1: Optional[client.NetworkingV1Api] = None
        self._init_error: Optional[str] = None
        self._init_client()

    def _init_client(self) -> None:
        try:
            if "KUBERNETES_SERVICE_HOST" in os.environ:
                config.load_incluster_config()
            else:
                config.load_kube_config(
                    config_file=self.kubeconfig_path,
                    context=self.context_name,
                )
            # Configure shorter timeout for responsive offline fallback
            c = client.Configuration.get_default_copy()
            c.retries = 0
            self._v1 = client.CoreV1Api(client.ApiClient(c))
            self._apps_v1 = client.AppsV1Api(client.ApiClient(c))
            self._networking_v1 = client.NetworkingV1Api(client.ApiClient(c))
            self._initialized = True
        except Exception as e:
            self._initialized = False
            self._init_error = str(e)

    def check_connection(self) -> Dict[str, Any]:
        """Test live Kubernetes API server connectivity."""
        if not self._initialized or not self._v1:
            return {
                "connected": False,
                "error": self._init_error or "Kubernetes client not initialized",
                "kubeconfig": self.kubeconfig_path or "~/.kube/config",
            }
        try:
            version_info = client.VersionApi(self._v1.api_client).get_code()
            nodes = self._v1.list_node(limit=5)
            return {
                "connected": True,
                "server_version": f"v{version_info.major}.{version_info.minor}",
                "git_version": version_info.git_version,
                "node_count": len(nodes.items),
                "nodes": [n.metadata.name for n in nodes.items if n.metadata and n.metadata.name],
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
                "kubeconfig": self.kubeconfig_path or "~/.kube/config",
            }

    def inspect_pod(self, namespace: str, pod_name: str) -> Dict[str, Any]:
        """Fetch complete real-world Pod context, securityContext, and volumes."""
        if not self._initialized or not self._v1:
            return {
                "found": False,
                "namespace": namespace,
                "pod_name": pod_name,
                "error": f"Kubernetes client unavailable: {self._init_error}",
            }

        try:
            pod = self._v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        except ApiException as e:
            if e.status == 404:
                return {
                    "found": False,
                    "namespace": namespace,
                    "pod_name": pod_name,
                    "message": f"Pod '{pod_name}' not found in namespace '{namespace}' (may have been terminated or recreated).",
                }
            raise RuntimeError(f"Kubernetes API error ({e.status}): {e.reason}")

        metadata = pod.metadata
        spec = pod.spec
        status = pod.status

        # Extract container security profiles
        containers_info: List[Dict[str, Any]] = []
        if spec and spec.containers:
            for c in spec.containers:
                sec = c.security_context
                sec_dict: Dict[str, Any] = {}
                if sec:
                    sec_dict = {
                        "privileged": getattr(sec, "privileged", None),
                        "read_only_root_filesystem": getattr(sec, "read_only_root_filesystem", None),
                        "run_as_user": getattr(sec, "run_as_user", None),
                        "run_as_non_root": getattr(sec, "run_as_non_root", None),
                        "allow_privilege_escalation": getattr(sec, "allow_privilege_escalation", None),
                        "capabilities": {
                            "add": list(sec.capabilities.add) if sec.capabilities and sec.capabilities.add else [],
                            "drop": list(sec.capabilities.drop) if sec.capabilities and sec.capabilities.drop else [],
                        } if getattr(sec, "capabilities", None) else {},
                    }
                containers_info.append({
                    "name": c.name,
                    "image": c.image,
                    "command": c.command,
                    "args": c.args,
                    "security_context": sec_dict,
                })

        # Identify risky volume mounts (e.g. hostPath)
        host_path_volumes = []
        if spec and spec.volumes:
            for v in spec.volumes:
                if v.host_path:
                    host_path_volumes.append({
                        "name": v.name,
                        "path": v.host_path.path,
                        "type": v.host_path.type,
                    })

        # Owner references (e.g. Deployment / DaemonSet)
        owners = []
        if metadata and metadata.owner_references:
            for o in metadata.owner_references:
                owners.append({
                    "kind": o.kind,
                    "name": o.name,
                    "controller": o.controller,
                })

        pod_labels = metadata.labels if metadata and metadata.labels else {}

        return {
            "found": True,
            "name": metadata.name if metadata else pod_name,
            "namespace": metadata.namespace if metadata else namespace,
            "node_name": spec.node_name if spec else None,
            "service_account": spec.service_account_name if spec else None,
            "host_network": spec.host_network if spec else False,
            "host_pid": spec.host_pid if spec else False,
            "host_ipc": spec.host_ipc if spec else False,
            "labels": pod_labels,
            "owner_references": owners,
            "containers": containers_info,
            "host_path_volumes": host_path_volumes,
            "phase": status.phase if status else "Unknown",
            "pod_ip": status.pod_ip if status else None,
        }

    def generate_isolation_network_policy(
        self,
        namespace: str,
        pod_name: str,
        allow_dns: bool = True,
    ) -> Dict[str, Any]:
        """Generate a production Kubernetes NetworkPolicy manifest to isolate a compromised pod."""
        pod_info: Dict[str, Any] = {"found": False}
        if self._initialized and self._v1:
            try:
                pod_info = self.inspect_pod(namespace, pod_name)
            except Exception:
                pod_info = {"found": False}

        labels = pod_info.get("labels", {}) if pod_info.get("found") else {"app": pod_name}
        
        # Pick the most specific label for selector
        selector_match_labels = {}
        if "app.kubernetes.io/name" in labels:
            selector_match_labels["app.kubernetes.io/name"] = labels["app.kubernetes.io/name"]
        elif "app" in labels:
            selector_match_labels["app"] = labels["app"]
        elif labels:
            first_key = list(labels.keys())[0]
            selector_match_labels[first_key] = labels[first_key]
        else:
            selector_match_labels["pod-name"] = pod_name

        policy_name = f"quarantine-{pod_name[:30]}"

        egress_rules: List[Dict[str, Any]] = []
        if allow_dns:
            egress_rules.append({
                "to": [
                    {"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}},
                    {"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "coredns"}}},
                ],
                "ports": [
                    {"protocol": "UDP", "port": 53},
                    {"protocol": "TCP", "port": 53},
                ],
            })

        manifest = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": policy_name,
                "namespace": namespace,
                "labels": {
                    "secops.falco.io/quarantine": "true",
                    "secops.falco.io/target-pod": pod_name,
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": selector_match_labels,
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],  # Deny all ingress
                "egress": egress_rules,  # Deny all egress except DNS
            },
        }

        import yaml
        yaml_text = yaml.dump(manifest, sort_keys=False)
        return {
            "policy_name": policy_name,
            "namespace": namespace,
            "manifest_dict": manifest,
            "yaml": yaml_text,
            "remediation_command": f"kubectl apply -n {namespace} -f - <<EOF\n{yaml_text}EOF",
        }
