"""Falcosidekick & Falco Event Ingestion Client.

Interfaces with live Falcosidekick daemon, Falcosidekick UI API,
or local Falco JSON audit log streams. No mock data.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx


@dataclass
class FalcoEvent:
    """Represents a real Falco runtime security alert."""
    uuid: str = ""
    rule: str = ""
    priority: str = "Notice"
    source: str = "syscall"
    time: str = ""
    output: str = ""
    hostname: str = ""
    tags: List[str] = field(default_factory=list)
    output_fields: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FalcoEvent:
        return cls(
            uuid=str(data.get("uuid", data.get("id", ""))),
            rule=str(data.get("rule", "Unknown Rule")),
            priority=str(data.get("priority", "Notice")),
            source=str(data.get("source", "syscall")),
            time=str(data.get("time", datetime.now(timezone.utc).isoformat())),
            output=str(data.get("output", "")),
            hostname=str(data.get("hostname", "")),
            tags=list(data.get("tags", [])),
            output_fields=dict(data.get("output_fields", {})),
        )


@dataclass
class AlertCluster:
    """Aggregated group of repeated alerts for noise analysis and exception synthesis."""
    rule: str
    priority: str
    count: int
    first_seen: str
    last_seen: str
    namespaces: List[str]
    pods: List[str]
    processes: List[str]
    container_images: List[str]
    sample_outputs: List[str]
    raw_output_fields_samples: List[Dict[str, Any]]


class FalcoClient:
    """Client for Falcosidekick and Falco event sources."""

    def __init__(
        self,
        daemon_url: str = "http://localhost:2801",
        ui_url: str = "http://localhost:2802",
        auth_user: Optional[str] = None,
        auth_password: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.daemon_url = daemon_url.rstrip("/")
        self.ui_url = ui_url.rstrip("/")
        self.auth = (auth_user, auth_password) if auth_user and auth_password else None
        self.timeout = timeout

    async def check_daemon_health(self) -> Dict[str, Any]:
        """Check live Falcosidekick daemon status."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(f"{self.daemon_url}/healthz")
                return {
                    "reachable": resp.status_code == 200,
                    "status_code": resp.status_code,
                    "endpoint": f"{self.daemon_url}/healthz",
                    "response": resp.text.strip(),
                }
            except Exception as e:
                return {
                    "reachable": False,
                    "endpoint": f"{self.daemon_url}/healthz",
                    "error": str(e),
                }

    async def check_ui_health(self) -> Dict[str, Any]:
        """Check live Falcosidekick UI status."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(f"{self.ui_url}/healthz", auth=self.auth)
                return {
                    "reachable": resp.status_code == 200,
                    "status_code": resp.status_code,
                    "endpoint": f"{self.ui_url}/healthz",
                    "response": resp.text.strip(),
                }
            except Exception as e:
                return {
                    "reachable": False,
                    "endpoint": f"{self.ui_url}/healthz",
                    "error": str(e),
                }

    async def post_event_to_daemon(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send a real Falco event payload to Falcosidekick daemon."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.daemon_url}/", json=event_data)
            return {
                "status_code": resp.status_code,
                "success": 200 <= resp.status_code < 300,
                "response": resp.text.strip(),
            }

    async def query_ui_events(
        self,
        rule: Optional[str] = None,
        priority: Optional[str] = None,
        limit: int = 50,
        page: int = 1,
    ) -> List[FalcoEvent]:
        """Query live events from Falcosidekick UI API."""
        params: Dict[str, Any] = {"limit": limit, "page": page}
        if rule:
            params["rule"] = rule
        if priority:
            params["priority"] = priority

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Falcosidekick UI supports /api/v1/events/search or /api/v1/events
            url = f"{self.ui_url}/api/v1/events/search"
            try:
                resp = await client.get(url, params=params, auth=self.auth)
                if resp.status_code == 404:
                    url = f"{self.ui_url}/api/v1/events"
                    resp = await client.get(url, params=params, auth=self.auth)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as e:
                raise RuntimeError(f"Failed to query Falcosidekick UI at {url}: {e}")

        events_raw = data if isinstance(data, list) else data.get("events", data.get("results", []))
        return [FalcoEvent.from_dict(ev) for ev in events_raw]

    @staticmethod
    def load_events_from_json_file(file_path: str) -> List[FalcoEvent]:
        """Ingest real Falco JSON logs from a local file (e.g. /var/log/falco_events.json)."""
        events: List[FalcoEvent] = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, list):
                        events.extend(FalcoEvent.from_dict(e) for e in obj)
                    else:
                        events.append(FalcoEvent.from_dict(obj))
                except json.JSONDecodeError:
                    continue
        return events

    @staticmethod
    def cluster_alerts(events: List[FalcoEvent]) -> List[AlertCluster]:
        """Group repeated alerts by (rule, priority) and identify common noise signatures."""
        groups: Dict[tuple[str, str], List[FalcoEvent]] = defaultdict(list)
        for ev in events:
            groups[(ev.rule, ev.priority)].append(ev)

        clusters: List[AlertCluster] = []
        for (rule, priority), group in groups.items():
            namespaces = set()
            pods = set()
            processes = set()
            images = set()
            sample_outputs = []
            output_fields_samples = []

            for ev in group[:10]:
                sample_outputs.append(ev.output)
                output_fields_samples.append(ev.output_fields)

            for ev in group:
                f = ev.output_fields
                if "k8s.ns.name" in f and f["k8s.ns.name"]:
                    namespaces.add(str(f["k8s.ns.name"]))
                if "k8s.pod.name" in f and f["k8s.pod.name"]:
                    pods.add(str(f["k8s.pod.name"]))
                if "proc.name" in f and f["proc.name"]:
                    processes.add(str(f["proc.name"]))
                elif "proc.cmdline" in f and f["proc.cmdline"]:
                    processes.add(str(f["proc.cmdline"]).split()[0])
                if "container.image.repository" in f and f["container.image.repository"]:
                    images.add(str(f["container.image.repository"]))
                elif "container.image" in f and f["container.image"]:
                    images.add(str(f["container.image"]))

            sorted_events = sorted(group, key=lambda e: e.time)
            first_seen = sorted_events[0].time if sorted_events else ""
            last_seen = sorted_events[-1].time if sorted_events else ""

            clusters.append(
                AlertCluster(
                    rule=rule,
                    priority=priority,
                    count=len(group),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    namespaces=sorted(list(namespaces)),
                    pods=sorted(list(pods)),
                    processes=sorted(list(processes)),
                    container_images=sorted(list(images)),
                    sample_outputs=sample_outputs[:3],
                    raw_output_fields_samples=output_fields_samples[:3],
                )
            )

        # Sort clusters by frequency descending
        clusters.sort(key=lambda c: c.count, reverse=True)
        return clusters
