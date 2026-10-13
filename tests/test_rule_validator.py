import pytest
from falco_triage.rule_validator import FalcoRuleValidator


def test_validate_valid_exception_yaml():
    validator = FalcoRuleValidator()
    yaml_text = """
- rule: Terminal shell in container
  append: true
  exceptions:
    - name: allowed_maintenance
      fields: [k8s.ns.name, proc.name]
      comps: [=, =]
      values:
        - [kube-system, bash]
"""
    report = validator.validate_rule_yaml(yaml_text)
    assert report["valid"] is True
    assert len(report["errors"]) == 0


def test_detect_invalid_filtercheck_field():
    validator = FalcoRuleValidator()
    yaml_text = """
- rule: Terminal shell in container
  append: true
  exceptions:
    - name: broken_field
      fields: [k8s.ns.name, proc.cmdlie]
      comps: [=, =]
      values:
        - [default, bash]
"""
    report = validator.validate_rule_yaml(yaml_text)
    # proc.cmdlie should trigger warning/error with suggestion
    issues = report["errors"] + report["warnings"]
    assert any("proc.cmdlie" in i["message"] for i in issues)
    suggestion_found = any("proc.cmdline" in i.get("suggestion", "") for i in issues)
    assert suggestion_found


def test_detect_mismatched_comps_length():
    validator = FalcoRuleValidator()
    yaml_text = """
- rule: Terminal shell in container
  append: true
  exceptions:
    - name: mismatched_lengths
      fields: [k8s.ns.name, proc.name, container.image]
      comps: [=, =]
      values:
        - [default, bash, nginx]
"""
    report = validator.validate_rule_yaml(yaml_text)
    assert report["valid"] is False
    assert any("does not match number of fields" in e["message"] for e in report["errors"])
