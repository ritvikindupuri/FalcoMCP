import os
import tempfile
import pytest
from falco_triage.exception_engine import FalcoExceptionEngine


def test_create_structured_exception():
    engine = FalcoExceptionEngine()
    exc = engine.create_structured_exception_dict(
        rule_name="Terminal shell in container",
        exception_name="allowed_ci_runners",
        fields=["k8s.ns.name", "proc.name", "container.image.repository"],
        comps=["=", "=", "="],
        values=[["ci-runners", "bash", "gitlab/gitlab-runner"]],
    )

    assert exc["rule"] == "Terminal shell in container"
    assert exc["append"] is True
    assert len(exc["exceptions"]) == 1
    assert exc["exceptions"][0]["name"] == "allowed_ci_runners"
    assert exc["exceptions"][0]["fields"] == ["k8s.ns.name", "proc.name", "container.image.repository"]
    assert exc["exceptions"][0]["values"] == [["ci-runners", "bash", "gitlab/gitlab-runner"]]


def test_synthesize_least_privilege_exception():
    engine = FalcoExceptionEngine()
    samples = [
        {
            "k8s.ns.name": "monitoring",
            "k8s.pod.name": "node-exporter-abc",
            "proc.name": "node-exporter",
            "container.image.repository": "prom/node-exporter",
            "fd.name": "/etc/resolv.conf",
        },
        {
            "k8s.ns.name": "monitoring",
            "k8s.pod.name": "node-exporter-xyz",
            "proc.name": "node-exporter",
            "container.image.repository": "prom/node-exporter",
            "fd.name": "/etc/hosts",
        },
    ]

    res = engine.synthesize_from_output_fields(
        rule_name="Write below etc",
        output_fields_samples=samples,
        strategy="least_privilege",
    )

    assert res["rule"] == "Write below etc"
    assert res["append"] is True
    exc = res["exceptions"][0]
    assert "k8s.ns.name" in exc["fields"]
    assert "proc.name" in exc["fields"]
    assert "fd.name" in exc["fields"]
    # Two distinct file paths
    assert len(exc["values"]) == 2


def test_append_and_merge_to_file():
    engine = FalcoExceptionEngine()
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".yaml") as tmp:
        tmp_path = tmp.name

    try:
        exc1 = engine.create_structured_exception_dict(
            rule_name="Write below etc",
            exception_name="known_writers",
            fields=["k8s.ns.name", "proc.name"],
            comps=["=", "="],
            values=[["kube-system", "kubelet"]],
        )
        res1 = engine.append_to_file(tmp_path, exc1)
        assert res1["action"] == "appended"

        # Now merge a new value into the same rule and exception
        exc2 = engine.create_structured_exception_dict(
            rule_name="Write below etc",
            exception_name="known_writers",
            fields=["k8s.ns.name", "proc.name"],
            comps=["=", "="],
            values=[["monitoring", "node-exporter"]],
        )
        res2 = engine.append_to_file(tmp_path, exc2)
        assert res2["action"] == "merged"

        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "kubelet" in content
        assert "node-exporter" in content
        assert "append: true" in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
