"""CNCF Falco Rule & Exception Syntax Validator.

Validates Falco YAML rules and exceptions against official Falco filtercheck fields,
operators, and schema requirements. Catches common mistakes before they cause
CrashLoopBackOff in production.
"""

from __future__ import annotations

import difflib
from typing import Any, Dict, List, Optional
from ruamel.yaml import YAML

# Standard Falco filtercheck field prefixes and common fields
KNOWN_FALCO_FIELDS = {
    # Process fields
    "proc.name", "proc.cmdline", "proc.pname", "proc.pcmdline", "proc.pid",
    "proc.ppid", "proc.apid", "proc.aname", "proc.exepath", "proc.args",
    "proc.env", "proc.cwd", "proc.is_exe_writable", "proc.is_exe_upper_layer",
    # File descriptor fields
    "fd.name", "fd.directory", "fd.filename", "fd.type", "fd.sip", "fd.dip",
    "fd.sport", "fd.dport", "fd.rip", "fd.rport", "fd.lip", "fd.lport",
    "fd.num", "fd.ip", "fd.port", "fd.connected",
    # Container fields
    "container.id", "container.name", "container.image", "container.image.repository",
    "container.image.tag", "container.image.digest", "container.privileged",
    "container.duration", "container.mounts",
    # Kubernetes fields
    "k8s.ns.name", "k8s.pod.name", "k8s.pod.id", "k8s.pod.label", "k8s.deployment.name",
    "k8s.serviceaccount.name", "k8s.daemonset.name", "k8s.statefulset.name",
    # User / Group fields
    "user.name", "user.uid", "user.loginuid", "user.homedir", "group.name", "group.gid",
    # Event fields
    "evt.type", "evt.time", "evt.num", "evt.dir", "evt.cpu", "evt.args",
    "evt.info", "evt.res", "evt.rawres",
}

VALID_COMPS = {
    "=", "==", "!=", "in", "pmatch", "startswith", "endswith", "glob",
    "contains", "icontains", "intersects", "<", "<=", ">", ">="
}

VALID_PRIORITIES = {
    "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE",
    "INFORMATIONAL", "DEBUG"
}


class RuleValidationError:
    def __init__(self, message: str, level: str = "ERROR", suggestion: Optional[str] = None):
        self.message = message
        self.level = level  # "ERROR" or "WARNING"
        self.suggestion = suggestion

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"level": self.level, "message": self.message}
        if self.suggestion:
            d["suggestion"] = self.suggestion
        return d


class FalcoRuleValidator:
    """Validates Falco rules and structured exceptions."""

    def __init__(self):
        self.yaml = YAML()

    def validate_field_name(self, field_name: str) -> Optional[RuleValidationError]:
        """Check if a field name is a recognized Falco filtercheck field."""
        # Handle parameterized fields like k8s.pod.label[...] or proc.aname[...]
        base_field = field_name.split("[")[0].strip()

        if base_field in KNOWN_FALCO_FIELDS:
            return None

        # Check for known prefixes
        prefixes = ("proc.", "fd.", "container.", "k8s.", "user.", "group.", "evt.", "syslog.")
        if any(base_field.startswith(p) for p in prefixes):
            # Known prefix but unverified suffix - check close matches
            matches = difflib.get_close_matches(base_field, list(KNOWN_FALCO_FIELDS), n=1, cutoff=0.7)
            suggestion = f"Did you mean '{matches[0]}'?" if matches else None
            return RuleValidationError(
                message=f"Field '{field_name}' looks like a Falco field but is not in the standard set.",
                level="WARNING",
                suggestion=suggestion,
            )

        matches = difflib.get_close_matches(base_field, list(KNOWN_FALCO_FIELDS), n=1, cutoff=0.6)
        suggestion = f"Did you mean '{matches[0]}'?" if matches else None
        return RuleValidationError(
            message=f"Unrecognized Falco filtercheck field '{field_name}'.",
            level="ERROR",
            suggestion=suggestion,
        )

    def validate_exception_block(self, exc: Dict[str, Any]) -> List[RuleValidationError]:
        """Validate a single structured exception block."""
        errors: List[RuleValidationError] = []

        if not isinstance(exc, dict):
            errors.append(RuleValidationError("Exception block must be a YAML mapping (dictionary)."))
            return errors

        if "name" not in exc or not exc["name"]:
            errors.append(RuleValidationError("Exception block is missing required 'name' field."))

        if "fields" not in exc:
            errors.append(RuleValidationError(f"Exception '{exc.get('name', '')}' is missing 'fields'."))
            return errors

        fields = exc["fields"]
        fields_list = fields if isinstance(fields, list) else [fields]

        for f in fields_list:
            err = self.validate_field_name(str(f))
            if err:
                errors.append(err)

        if "comps" in exc:
            comps = exc["comps"]
            comps_list = comps if isinstance(comps, list) else [comps]

            if isinstance(fields, list) and len(comps_list) != len(fields_list):
                errors.append(RuleValidationError(
                    f"Number of comparison operators ({len(comps_list)}) does not match number of fields ({len(fields_list)})."
                ))

            for c in comps_list:
                if str(c).lower() not in VALID_COMPS:
                    errors.append(RuleValidationError(
                        f"Invalid comparison operator '{c}'. Supported: {', '.join(sorted(VALID_COMPS))}"
                    ))

        if "values" not in exc:
            errors.append(RuleValidationError(f"Exception '{exc.get('name', '')}' is missing 'values'."))
        else:
            values = exc["values"]
            if not isinstance(values, list):
                errors.append(RuleValidationError("'values' must be a list."))
            elif isinstance(fields, list) and len(fields_list) > 1:
                # Multi-field tuple check
                for i, row in enumerate(values):
                    if not isinstance(row, (list, tuple)) or len(row) != len(fields_list):
                        errors.append(RuleValidationError(
                            f"Row {i} in 'values' has length {len(row) if isinstance(row, (list, tuple)) else 1}, expected {len(fields_list)} to match fields {fields_list}."
                        ))

        return errors

    def validate_rule_yaml(self, yaml_content: str) -> Dict[str, Any]:
        """Validate a full Falco YAML rules string or snippet."""
        try:
            docs = self.yaml.load(yaml_content)
        except Exception as e:
            return {
                "valid": False,
                "errors": [{"level": "FATAL", "message": f"YAML syntax error: {str(e)}"}],
                "warnings": [],
            }

        if docs is None:
            return {"valid": False, "errors": [{"level": "ERROR", "message": "YAML document is empty."}], "warnings": []}

        rules_list = docs if isinstance(docs, list) else [docs]
        errors: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        for item in rules_list:
            if not isinstance(item, dict):
                errors.append({"level": "ERROR", "message": f"Rule element must be a dictionary, got {type(item).__name__}"})
                continue

            # Check if this is an exception override or base rule
            is_rule = "rule" in item
            is_macro = "macro" in item
            is_list = "list" in item

            if not (is_rule or is_macro or is_list):
                errors.append({"level": "ERROR", "message": "Item is missing 'rule', 'macro', or 'list' key."})
                continue

            if is_rule:
                rule_name = item.get("rule", "unnamed")
                # If not append override, check mandatory base rule fields
                is_override = item.get("append") is True
                if not is_override:
                    if "condition" not in item:
                        errors.append({"level": "ERROR", "message": f"Rule '{rule_name}' missing required 'condition'."})
                    if "output" not in item:
                        errors.append({"level": "ERROR", "message": f"Rule '{rule_name}' missing required 'output'."})
                    if "priority" not in item:
                        errors.append({"level": "ERROR", "message": f"Rule '{rule_name}' missing required 'priority'."})
                    elif str(item.get("priority")).upper() not in VALID_PRIORITIES:
                        errors.append({"level": "ERROR", "message": f"Invalid priority '{item.get('priority')}'. Expected one of {sorted(VALID_PRIORITIES)}."})

                # Validate exceptions block if present
                if "exceptions" in item:
                    for exc in item["exceptions"]:
                        for e in self.validate_exception_block(exc):
                            d = e.to_dict()
                            if e.level == "ERROR":
                                errors.append(d)
                            else:
                                warnings.append(d)

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "rules_inspected": len(rules_list),
        }
