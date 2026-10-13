"""CNCF Falco 0.35+ Structured Exception Engine.

Generates production-grade, least-privilege Falco rule exceptions adhering to the
official specification:
  - rule: <name>
    append: true
    exceptions:
      - name: <exception_name>
        fields: [...]
        comps: [...]
        values: [...]

Preserves comments and formatting using ruamel.yaml.
"""

from __future__ import annotations

import os
from io import StringIO
from typing import Any, Dict, List, Optional, Union
from ruamel.yaml import YAML


class FalcoExceptionEngine:
    """Generates and manages structured Falco rule exceptions."""

    def __init__(self):
        self.yaml = YAML()
        self.yaml.preserve_quotes = True

    def create_structured_exception_dict(
        self,
        rule_name: str,
        exception_name: str,
        fields: Union[str, List[str]],
        comps: Union[str, List[str]],
        values: List[Any],
    ) -> Dict[str, Any]:
        """Build the dict structure for a single Falco rule exception."""
        if isinstance(fields, str):
            fields_val = fields
            comps_val = comps
        else:
            fields_val = list(fields)
            comps_val = list(comps) if isinstance(comps, list) else [comps] * len(fields)

        formatted_values = []
        if isinstance(fields, list) and len(fields) > 1:
            for v in values:
                if isinstance(v, (list, tuple)):
                    formatted_values.append(list(v))
                else:
                    formatted_values.append([v])
        else:
            formatted_values = list(values)

        return {
            "rule": rule_name,
            "append": True,
            "exceptions": [
                {
                    "name": exception_name,
                    "fields": fields_val,
                    "comps": comps_val,
                    "values": formatted_values,
                }
            ],
        }

    def to_yaml_string(self, exception_rule: Dict[str, Any]) -> str:
        """Convert an exception rule dict to cleanly formatted Falco YAML."""
        buf = StringIO()
        self.yaml.dump([exception_rule], buf)
        return buf.getvalue()

    def synthesize_from_output_fields(
        self,
        rule_name: str,
        output_fields_samples: List[Dict[str, Any]],
        strategy: str = "least_privilege",
        exception_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synthesize a structured exception from real Falco event output_fields."""
        if not output_fields_samples:
            raise ValueError("Cannot synthesize exception without sample output_fields")

        unique_tuples = set()
        has_file = any("fd.name" in s for s in output_fields_samples)

        if strategy == "least_privilege":
            if has_file:
                fields = ["k8s.ns.name", "proc.name", "container.image.repository", "fd.name"]
                comps = ["=", "=", "=", "startswith"]
            else:
                fields = ["k8s.ns.name", "proc.name", "container.image.repository"]
                comps = ["=", "=", "="]
        elif strategy == "namespace_process":
            fields = ["k8s.ns.name", "proc.name"]
            comps = ["=", "="]
        elif strategy == "container_process":
            fields = ["container.image.repository", "proc.name"]
            comps = ["=", "="]
        elif strategy == "process_only":
            fields = ["proc.name"]
            comps = ["="]
        else:
            raise ValueError(f"Unknown exception strategy: {strategy}")

        for s in output_fields_samples:
            row = []
            for f in fields:
                val = s.get(f)
                if not val:
                    if f == "proc.name" and "proc.cmdline" in s:
                        val = str(s["proc.cmdline"]).split()[0]
                    elif f == "container.image.repository" and "container.image" in s:
                        val = str(s["container.image"]).split(":")[0]
                    elif f == "k8s.ns.name":
                        val = "default"
                    elif f == "fd.name":
                        val = "/var/log"
                    else:
                        val = "unknown"
                row.append(str(val))
            unique_tuples.add(tuple(row))

        values_list = [list(t) for t in sorted(unique_tuples)]

        if not exception_name:
            clean_rule = rule_name.lower().replace(" ", "_").replace("-", "_")
            primary_proc = values_list[0][1] if len(values_list[0]) > 1 else values_list[0][0]
            primary_proc = primary_proc.replace("/", "_").replace(".", "_")
            exception_name = f"allow_{primary_proc}_{clean_rule}"[:50]

        return self.create_structured_exception_dict(
            rule_name=rule_name,
            exception_name=exception_name,
            fields=fields,
            comps=comps,
            values=values_list,
        )

    def append_to_file(self, file_path: str, new_exception: Dict[str, Any]) -> Dict[str, Any]:
        """Safely append or merge the exception into a falco_rules.local.yaml file."""
        existing_rules: List[Any] = []
        file_existed = os.path.exists(file_path)

        if file_existed:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    parsed = self.yaml.load(content)
                    if isinstance(parsed, list):
                        existing_rules = parsed
                    elif isinstance(parsed, dict):
                        existing_rules = [parsed]

        target_rule_name = new_exception.get("rule")
        new_exc_item = new_exception.get("exceptions", [])[0]
        merged = False

        for r in existing_rules:
            if isinstance(r, dict) and r.get("rule") == target_rule_name:
                r["append"] = True
                if "exceptions" not in r or not isinstance(r["exceptions"], list):
                    r["exceptions"] = []
                
                exc_found = False
                for exc in r["exceptions"]:
                    if isinstance(exc, dict) and exc.get("name") == new_exc_item.get("name"):
                        existing_values = exc.get("values", [])
                        for v in new_exc_item.get("values", []):
                            if v not in existing_values:
                                existing_values.append(v)
                        exc["values"] = existing_values
                        exc_found = True
                        break

                if not exc_found:
                    r["exceptions"].append(new_exc_item)
                merged = True
                break

        if not merged:
            existing_rules.append(new_exception)

        with open(file_path, "w", encoding="utf-8") as f:
            self.yaml.dump(existing_rules, f)

        return {
            "file_path": file_path,
            "action": "merged" if merged else "appended",
            "rule": target_rule_name,
            "exception_name": new_exc_item.get("name"),
            "values_count": len(new_exc_item.get("values", [])),
        }
