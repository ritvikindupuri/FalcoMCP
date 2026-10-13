# Falco Container Security & Rule Tuning Rules

When assisting with Falco runtime security alerts, Kubernetes incident triage, or rule tuning, follow these mandatory security guidelines:

## 1. Never Blanket-Suppress High Severity Alerts
* Alerts marked `CRITICAL`, `ALERT`, or `EMERGENCY` (e.g. core namespace privilege escalations, kernel exploits, root container escapes) must NEVER be silenced with loose process-level exceptions.
* Always correlate the offending workload using `correlate_k8s_workload` first to evaluate whether the activity is legitimate infrastructure maintenance or active exploitation.

## 2. Enforce Least-Privilege Scoping on Exceptions
* When generating Falco structured exceptions (`append: true`), do NOT scope solely by `proc.name`.
* Default to the **`least_privilege`** strategy: bind the exception to at least `[k8s.ns.name, proc.name, container.image.repository]`, and include `fd.name` (with operator `startswith`) if filesystem access is involved.
* If a process is legitimate only for a specific daemon (e.g. `datadog-agent` reading `/etc/shadow`), ensure the container image repository is strictly pinned.

## 3. Pre-Flight Rule Validation
* Never write unverified YAML directly to `falco_rules.local.yaml`.
* Always run `validate_falco_rule` to ensure filtercheck field names (`proc.*`, `fd.*`, `k8s.*`, `container.*`), operator lengths, and tuple row counts conform to CNCF Falco 0.35+ specifications.

## 4. Active Threat Isolation Over Suppression
* If an alert indicates unexpected interactive shells (`Terminal shell in container`) or anomalous outbound connections from an unknown container image, propose immediate containment via `generate_pod_isolation_policy` instead of muting the alert.
