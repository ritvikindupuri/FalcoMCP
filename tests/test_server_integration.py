import pytest
import os
import tempfile
import json
from falco_triage.server import (
    app,
    check_lab_environment,
    dispatch_test_falco_alert,
    ingest_falco_alerts,
    correlate_k8s_workload,
    generate_falco_exception,
    append_falco_exception_to_file,
    validate_falco_rule,
    generate_pod_isolation_policy,
    bootstrap_kind_cluster,
    deploy_falcosidekick_to_kubernetes,
    deploy_sample_k8s_workloads,
    install_falco_to_kubernetes,
    prompt_path1_live_cluster_triage,
    prompt_path2_bootstrap_sandbox_lab,
    prompt_spin_up_sample_cluster_and_workloads,
    prompt_tune_noisy_rule,
    prompt_isolate_compromised_pod,
)
from falco_triage.lab_bootstrap import REAL_FALCO_EVENT_TEMPLATES


@pytest.mark.asyncio
async def test_server_check_lab_environment():
    status = await check_lab_environment()
    assert "docker" in status
    assert "kubernetes" in status
    assert "falcosidekick_daemon" in status
    assert "falcosidekick_ui" in status


def test_server_validate_falco_rule():
    yaml_valid = """
- rule: Terminal shell in container
  append: true
  exceptions:
    - name: allow_bash
      fields: [proc.name]
      comps: [=]
      values: [bash]
"""
    res = validate_falco_rule(yaml_valid)
    assert res["valid"] is True
    assert res["rules_inspected"] == 1


def test_server_generate_and_append_exception():
    samples = [
        REAL_FALCO_EVENT_TEMPLATES["write_below_etc"]["output_fields"]
    ]
    gen_res = generate_falco_exception(
        rule_name="Write below etc",
        output_fields_samples=samples,
        strategy="least_privilege",
    )
    assert gen_res["rule_name"] == "Write below etc"
    assert gen_res["validation"]["valid"] is True

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".yaml") as tmp:
        tmp_path = tmp.name

    try:
        append_res = append_falco_exception_to_file(
            file_path=tmp_path,
            exception_yaml=gen_res["yaml_content"],
        )
        assert append_res["action"] == "appended"
        assert append_res["rule"] == "Write below etc"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@pytest.mark.asyncio
async def test_server_ingest_from_file():
    events_raw = [
        REAL_FALCO_EVENT_TEMPLATES["shell_in_container"],
        REAL_FALCO_EVENT_TEMPLATES["read_sensitive_file"],
    ]
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tmp:
        for e in events_raw:
            tmp.write(json.dumps(e) + "\n")
        tmp_path = tmp.name

    try:
        res = await ingest_falco_alerts(source="file", file_path=tmp_path)
        assert res["total_events_ingested"] == 2
        assert res["total_clusters"] == 2
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_server_isolation_policy():
    res = generate_pod_isolation_policy(namespace="default", pod_name="test-pod")
    assert "quarantine-test-pod" in res["policy_name"]
    assert "NetworkPolicy" in res["yaml"]


def test_server_prompts():
    p_path1 = prompt_path1_live_cluster_triage()
    assert len(p_path1) > 0
    assert "ingest_falco_alerts" in p_path1[0]["content"]

    p_path2 = prompt_path2_bootstrap_sandbox_lab()
    assert len(p_path2) > 0
    assert "check_lab_environment" in p_path2[0]["content"]

    p_sample = prompt_spin_up_sample_cluster_and_workloads()
    assert len(p_sample) > 0
    assert "deploy_sample_k8s_workloads" in p_sample[0]["content"]

    p2 = prompt_tune_noisy_rule("Write below etc")
    assert "Write below etc" in p2[0]["content"]

    p3 = prompt_isolate_compromised_pod("default", "rogue-pod")
    assert "rogue-pod" in p3[0]["content"]
