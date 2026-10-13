import pytest
from falco_triage.k8s_client import K8sClient


def test_generate_isolation_network_policy():
    client = K8sClient()
    policy = client.generate_isolation_network_policy(
        namespace="production",
        pod_name="api-gateway-5f7b8c9d0-12345",
        allow_dns=True,
    )

    assert policy["policy_name"] == "quarantine-api-gateway-5f7b8c9d0-12345"
    assert policy["namespace"] == "production"
    assert "NetworkPolicy" in policy["yaml"]
    assert "kube-dns" in policy["yaml"] or "coredns" in policy["yaml"]
    assert "Ingress" in policy["manifest_dict"]["spec"]["policyTypes"]
    assert "Egress" in policy["manifest_dict"]["spec"]["policyTypes"]
    assert policy["manifest_dict"]["spec"]["ingress"] == []  # Deny ingress
