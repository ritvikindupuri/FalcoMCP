---
name: falco-triage
description: >-
  Use this skill when investigating Falco runtime security alerts, tuning noisy Falco rules,
  eliminating false positives in Kubernetes, creating CNCF Falco structured exceptions (append: true),
  correlating alerts with live pods, or setting up a fresh local Falco testing sandbox.
---

# Falco Runtime Security Triage & Rule Tuning Runbook

This skill operates in **Two First-Class Modes** depending on the user's infrastructure state:

```
                      +----------------------------------------+
                      ¦        Which path are you on?          ¦
                      +----------------------------------------+
                                         ¦
                 +-----------------------------------------------+
                 ?                                               ?
   +---------------------------+                   +---------------------------+
   ¦          PATH 1           ¦                   ¦          PATH 2           ¦
   ¦  "Live Cluster Triage"    ¦                   ¦  "Sandbox Lab Bootstrap"  ¦
   ¦                           ¦                   ¦                           ¦
   ¦ User has Falco + K8s      ¦                   ¦ User needs a fresh lab or ¦
   ¦ already running.          ¦                   ¦ wants to test from scratch¦
   ¦                           ¦                   ¦                           ¦
   ¦ • Ingest live alerts      ¦                   ¦ • Auto-check Docker & K8s ¦
   ¦ • Correlate active pods   ¦                   ¦ • Spin up fresh Kind/pod  ¦
   ¦ • Scope least-privilege   ¦                   ¦ • Deploy Falcosidekick    ¦
   ¦ • Append to rules file    ¦                   ¦ • Inject test alerts      ¦
   +---------------------------+                   +---------------------------+
```

---

## PATH 1: Live Cluster Triage & Rule Tuning (Existing Infrastructure)

Use this path when the user already has an active Kubernetes cluster and running Falco/Falcosidekick deployment.

### Trigger Prompts:
* *"Triage recent alerts from Falcosidekick."*
* *"We are getting 500 alerts a day from `Write below etc` in the monitoring namespace, tune this rule."*
* *"Investigate pod `auth-svc-123` in namespace `prod` and quarantine it if needed."*

### Step-by-Step Procedure:

1. **Ingest & Cluster Alerts**:
   Call `ingest_falco_alerts` with:
   * `source="falcosidekick"`
   * `falcosidekick_ui_url`: e.g. `http://localhost:2802` or cluster endpoint
   * `rule_filter`: (optional) target rule causing alert fatigue
   * Pinpoint the highest-frequency rules and offending pods.

2. **Correlate with Live Workload**:
   Call `correlate_k8s_workload(namespace, pod_name)`:
   * Verify if the pod is `privileged`, has elevated Linux capabilities, or mounts `hostPath`.
   * Check if it is a legitimate `DaemonSet` (e.g. Datadog, Prometheus node-exporter) or an untrusted pod.

3. **Threat vs. False Positive Decision**:
   * **If Benign Background Daemon**:
     1. Call `generate_falco_exception` with `strategy="least_privilege"`.
     2. Verify with `validate_falco_rule`.
     3. Append to `falco_rules.local.yaml` using `append_falco_exception_to_file`.
   * **If Active Threat / Rogue Shell**:
     1. Propose immediate isolation with `generate_pod_isolation_policy(namespace, pod_name)`.
     2. Never silence active exploitation.

---

## PATH 2: Zero-to-One Sandbox Lab Bootstrap (Fresh Setup via Natural Language)

Use this path when the user **does not** have Falco running, wants to test rules in a sandbox, or wants to create fresh clusters/containers.

### Trigger Prompts:
* *"Set up a local Falco testing lab for me from scratch."*
* *"Spin up a fresh Kubernetes cluster and deploy Falcosidekick."*
* *"I don't have Falco running yet. Deploy a test environment and send a sample alert so I can test tuning."*

### Step-by-Step Procedure:

1. **Preflight Environment Check**:
   Call `check_lab_environment` to inspect Docker daemon, Kubernetes connectivity, and port availability.

2. **Option A: Containerized Sandbox (Fastest)**:
   * Call `bootstrap_falcosidekick_lab(daemon_port=2801, ui_port=2802)`.
   * If Docker Desktop is stopped, the tool automatically initiates launch on Windows.
   * Runs clean, official `falcosecurity/falcosidekick` and `falcosecurity/falcosidekick-ui` containers.

3. **Option B: Full Kubernetes Cluster Sandbox**:
   * Call `bootstrap_kind_cluster(cluster_name="falco-lab", recreate=True)` to create a fresh isolated Kind cluster.
   * Call `deploy_falcosidekick_to_kubernetes` to apply the official Falcosidekick and UI deployments directly into the cluster.

4. **Dispatch Realistic Alert Payloads**:
   Call `dispatch_test_falco_alert` using pre-built real-world templates:
   * `shell_in_container`: Simulates interactive bash spawned in a web pod.
   * `write_below_etc`: Simulates node-exporter writing to `/etc/resolv.conf`.
   * `read_sensitive_file`: Simulates datadog-agent reading `/etc/shadow`.

5. **Walkthrough Tuning**:
   Once the alert lands in the live UI (`http://localhost:2802`), query it back using `ingest_falco_alerts` and guide the user through creating their first structured exception!
