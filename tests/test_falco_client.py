import json
import os
import tempfile
import pytest
from falco_triage.falco_client import FalcoClient, FalcoEvent
from falco_triage.lab_bootstrap import REAL_FALCO_EVENT_TEMPLATES


def test_falco_event_from_dict():
    raw = REAL_FALCO_EVENT_TEMPLATES["shell_in_container"]
    event = FalcoEvent.from_dict(raw)

    assert event.rule == "Terminal shell in container"
    assert event.priority == "Notice"
    assert event.output_fields["proc.name"] == "bash"
    assert event.output_fields["k8s.pod.name"] == "web-frontend-79f8b4d6b-x9zlq"


def test_cluster_alerts():
    raw1 = REAL_FALCO_EVENT_TEMPLATES["shell_in_container"]
    raw2 = dict(raw1)
    raw2["output_fields"] = {**raw1["output_fields"], "k8s.pod.name": "web-frontend-2"}

    raw3 = REAL_FALCO_EVENT_TEMPLATES["write_below_etc"]

    events = [
        FalcoEvent.from_dict(raw1),
        FalcoEvent.from_dict(raw2),
        FalcoEvent.from_dict(raw3),
    ]

    clusters = FalcoClient.cluster_alerts(events)
    assert len(clusters) == 2
    # shell_in_container has 2 occurrences
    assert clusters[0].rule == "Terminal shell in container"
    assert clusters[0].count == 2
    assert "bash" in clusters[0].processes
    assert len(clusters[0].pods) == 2


def test_load_events_from_json_file():
    events_raw = [
        REAL_FALCO_EVENT_TEMPLATES["shell_in_container"],
        REAL_FALCO_EVENT_TEMPLATES["read_sensitive_file"],
    ]

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tmp:
        for e in events_raw:
            tmp.write(json.dumps(e) + "\n")
        tmp_path = tmp.name

    try:
        loaded = FalcoClient.load_events_from_json_file(tmp_path)
        assert len(loaded) == 2
        assert loaded[0].rule == "Terminal shell in container"
        assert loaded[1].rule == "Read sensitive file untrusted"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
