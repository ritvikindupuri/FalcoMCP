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

## 5. Standard MCP Server & Tool Overview Response
When the user asks what the Falco MCP server is and what tools you have access to, you MUST provide:
1. Clear description of what the Falco-Triage server does (Autonomous Kubernetes Runtime Security & CNCF Falco Rule-Tuning Copilot with zero mock data).
2. The exact categorized tool list:
   * **Lab & Environment Setup**: `check_lab_environment`, `bootstrap_falcosidekick_lab`, `bootstrap_kind_cluster`, `install_falco_to_kubernetes`, `deploy_falcosidekick_to_kubernetes`, `deploy_sample_k8s_workloads`
   * **Triage & Investigation**: `ingest_falco_alerts`, `dispatch_test_falco_alert`, `correlate_k8s_workload`
   * **Rule Tuning & Mitigation**: `generate_falco_exception`, `append_falco_exception_to_file`, `validate_falco_rule`, `generate_pod_isolation_policy`
3. A dedicated **Quick-Action Prompts** copy-and-paste section covering:
   * **Server & Tools Discovery**: `"What is the Falco MCP server and what tools do you have access to?"`
   * **Real Test Data with Docker, Falco & K8s**: `"I have Docker, Kubernetes, and Falco installed per the setup guide. Please inspect my cluster, spin up sample Nginx and node-exporter workloads, deploy the Falcosidekick UI forwarder, and dispatch test alerts so I can test rule tuning."`
   * **Live Noise Reduction & Clustering**: `"Run ingest_falco_alerts to pull recent alerts from our Falcosidekick deployment at http://localhost:2802, cluster them by rule, and show me the top false positives."`
   * **Precision Rule Tuning**: `"We are getting hundreds of alerts from 'Read sensitive file untrusted' on datadog-agent in namespace monitoring. Correlate the pod and generate a least-privilege Falco structured exception."`
   * **Immediate Threat Quarantine**: `"Investigate pod web-frontend in namespace default using correlate_k8s_workload. If an unexpected interactive shell spawned, generate a zero-trust NetworkPolicy to isolate it immediately."`
   * **Docker-Only Lightweight Lab**: `"Launch a fresh Falcosidekick testing lab in Docker using bootstrap_falcosidekick_lab and send a test shell_in_container alert."`
   * **Offline Rule Linting & Exception Synthesis**: `"Validate this Falco rule YAML and tell me if the filtercheck fields, operators, and tuple structures conform to CNCF Falco 0.35+ specs."`

## 6. Execution Transparency & Human Approval UX
When executing actions or responding to user requests:
1. **Command Transparency with Collapsible Output**:
   * For every executed command or tool action, clearly present the command line or tool invocation.
   * Format the resulting output in a collapsible markdown dropdown block (`<details><summary><b>View Output / Logs (Click to expand)</b></summary>...</details>`) right underneath so the user can easily click to inspect details without cluttering the chat.
2. **Human Approval for Sensitive Mutations**:
   * For state-changing operations that modify clusters or write files (e.g. `append_falco_exception_to_file`, applying NetworkPolicies to clusters, or deploying pods), you MUST NOT print plain markdown bullet lists.
   * You MUST call the **`ask_question`** tool to present actual interactive clickable buttons:
     * Question: Describe the exact pending mutation or command.
     * Options:
       * `"(Recommended) Allow: Approve execution for this action"`
       * `"Deny: Abort execution and keep cluster/files unchanged"`
       * `"Always (Auto-approve): Authorize this and subsequent operations for the session"`
   * If the user selects `Deny`, abort the action. If `Allow`, proceed with the single command. If `Always`, proceed and auto-approve future mutations in the session.

