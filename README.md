# Falco-Triage - Autonomous Container Security & Falco Rule Tuning Copilot

An intelligent Model Context Protocol (MCP) server and agentic plugin engineered for Container Security Engineers, DevSecOps practitioners, and Kubernetes Platform Operators. It connects AI assistants (Antigravity, Claude Code, Cursor) directly to live runtime alerts and active Kubernetes clusters to eliminate false positives, synthesize CNCF Falco 0.35+ structured exceptions, and generate quarantine NetworkPolicy manifests for suspicious pods.

---

 **Full Technical Documentation**: Read the complete [Technical Documentation & Architecture Specification](./docs/TECHNICAL_DOCUMENTATION.md) for in-depth subsystem breakdowns, data contracts, and security specifications.

---

## Key Features

* **Production-Grade Alert Ingestion**: Reads alerts over HTTP from the Falcosidekick UI API (`:2802/api/v1/events/search`, falling back to `/api/v1/events`) or from a local Falco JSON log (e.g. `/var/log/falco_events.json`). The Falcosidekick daemon (`:2801`) is only used for health checks and lab test-alert POSTs.
* **Multi-Dimensional Noise Clustering**: Groups alerts by `(rule, priority)`, ranks the groups by count, and lists the namespaces, pods, process names (falling back to the first token of `proc.cmdline`), and container image repositories seen in each group to identify top sources of alert fatigue.
* **Deep Kubernetes Workload Correlation**: Connects to the active cluster via the official Kubernetes API client (`~/.kube/config`, or in-cluster config when running inside a pod) and reads (read-only) the Pod's container specs, security contexts (`privileged`, capabilities, read-only root filesystem), `hostPath` volumes, labels, and owner references.
* **CNCF Falco 0.35+ Structured Exception Engine**: Automatically synthesizes precision, least-privilege exception blocks (`append: true`, `fields`, `comps`, `values`) and merges them into existing `falco_rules.local.yaml` files using a `ruamel.yaml` round-trip load/dump (existing rules are kept; comments generally survive, but formatting may be normalized).
* **Pre-Flight Filtercheck Rule Validator**: Validates rule/exception YAML (automatically inside `generate_falco_exception`, or on demand via `validate_falco_rule`), checking syntax, operator compatibility, tuple length alignment, and official Falco filtercheck fields (`proc.*`, `fd.*`, `container.*`, `k8s.*`, `user.*`, `evt.*`) with fuzzy typo suggestions.
* **Quarantine Manifest Generation**: Generates a locked-down Kubernetes `NetworkPolicy` (deny all ingress and egress except DNS on port 53) plus the matching `kubectl apply` command. The YAML is returned only; nothing is applied to the cluster.
* **Approval Flags**: Tools that write the rules file or produce a quarantine policy return `requires_human_approval: true` and `approval_options: [Allow, Deny, Always]`. Enforcing that approval is up to the MCP client.
* **Two Dedicated Operational Paths**:
  * **Path 1 (Live Cluster Triage)**: Triage active clusters, tune noisy production rules, and generate quarantine policies for suspicious pods.
  * **Path 2 (Zero-to-One Sandbox Bootstrap)**: Use Docker, Kind, kubectl, and Helm to start Falcosidekick (+ UI), create a Kind cluster, deploy sample pods, install Falco, and POST realistic test alerts.
* **Plugin Assets**: Runs as a standalone stdio MCP server; the repo also ships a minimal `plugin.json` manifest, a runbook (`skills/falco-triage/SKILL.md`), and agent guardrail instructions (`rules/AGENTS.md`). The guardrails are instructions for the AI client, not checks enforced by the server code.

---

## System Architecture

<p align="center">
  <img src="https://raw.githubusercontent.com/ritvikindupuri/FalcoMCP/main/assets/architecture.png" alt="Falco-Triage System Architecture Diagram" width="100%" />
</p>
<p align="center"><b>Figure 1: Falco-Triage components and data flows</b></p>

### Flow-by-Flow Explanation of the Architecture

Legend: blue = read, orange = write / execute, dashed = generated, not applied.

1. **prompt**: The **Security Engineer** types a request into the **MCP client** (Claude Code / Cursor / Antigravity), which can follow `skills/falco-triage/SKILL.md` and `rules/AGENTS.md`.
2. **tool calls (stdio) / results**: The client calls tools on the **MCP transport** (`MCPServer` over stdio, 13 tools + 5 prompts) and receives the results, including any approval flags.
3. **GET events :2802**: **Alert Ingestion** queries the **Falcosidekick UI** events API and clusters noisy alerts by rule, namespace, pod, process, and image.
4. **read JSON log**: Alternatively, **Alert Ingestion** reads a local **Falco JSON log** (`source="file"`).
5. **read pod (read-only)**: The **Workload Correlator** reads the flagged Pod from the **Kubernetes API** (pods & owners).
6. **YAML only, not applied**: The **Workload Correlator** generates a quarantine **NetworkPolicy** and returns it with a `kubectl apply` command. You apply it yourself if you choose to.
7. **append exception**: The **Exception Engine** builds least-privilege exceptions; `generate_falco_exception` runs them through the **Rule Validator**. `append_falco_exception_to_file` merges the exception into **falco_rules.local.yaml** with `ruamel.yaml`. It does not re-validate, so run `validate_falco_rule` first.
8. **run docker/kind/helm**: The **Lab Bootstrapper** (sandbox setup) runs Docker, kind, kubectl, and Helm as subprocesses.
9. **deploy to cluster**: Those tools deploy Falcosidekick (+ UI), sample pods, and Falco (via Helm) into the Kind/Kubernetes cluster.
10. **POST test alert :2801**: The **Lab Bootstrapper** POSTs sample Falco events to **Falcosidekick**.
11. **alerts / forward**: In the **Falco alert pipeline**, the **Falco engine** (eBPF sensor, a prerequisite or lab-installed via Helm) sends alerts to **Falcosidekick**, which forwards them to the **Falcosidekick UI**. The server never runs Falco itself.

---

## Tech Stack

| Layer | Technologies | Purpose |
| :--- | :--- | :--- |
| **Protocol & Agent** | Model Context Protocol (`mcp>=1.0.0`, locked 2.3.0; code uses `mcp.server.mcpserver.MCPServer`), Python 3.10+ | High-performance JSON-RPC tool and prompt routing |
| **Runtime Client** | `httpx>=0.27.0` (locked 0.28.1), `asyncio` | Asynchronous communication with Falcosidekick REST endpoints |
| **Kubernetes API** | `kubernetes>=30.0.0` (locked 37.0.0, official client); `PyYAML>=6.0` (locked 6.0.3; used by `k8s_client.py` to render NetworkPolicy YAML) | Cluster authentication, Pod inspection, NetworkPolicy YAML generation |
| **YAML Engine** | `ruamel.yaml>=0.18.0` (locked 0.19.1) | Comment-preserving, schema-accurate Falco YAML generation |
| **Data Validation** | `pydantic>=2.0.0` (locked 2.13.5; declared but not imported directly by `src/`) | Used through the MCP SDK |
| **Package Management** | `uv`, `hatchling` | Ultra-fast virtualenv creation and deterministic dependency resolution |
| **Testing & CI** | `pytest>=8.0.0` (locked 9.1.1), `pytest-asyncio>=0.23.0` (locked 1.4.0) | Full test suite covering 16 unit, schema, and integration tests |
| **Target Runtime** | Falco, Falcosidekick (+ UI), Kubernetes; Docker, Kind, kubectl, Helm for the lab path only | Live container security infrastructure |

### MCP Tools & Prompts (`src/falco_triage/server.py`)

**Tools (13):** `check_lab_environment`, `bootstrap_falcosidekick_lab`, `bootstrap_kind_cluster`, `deploy_falcosidekick_to_kubernetes`, `deploy_sample_k8s_workloads`, `install_falco_to_kubernetes`, `dispatch_test_falco_alert`, `ingest_falco_alerts`, `correlate_k8s_workload`, `generate_falco_exception`, `append_falco_exception_to_file`, `validate_falco_rule`, `generate_pod_isolation_policy`

**Prompts (5):** `path1_live_cluster_triage`, `path2_bootstrap_sandbox_lab`, `spin_up_sample_cluster_and_workloads`, `tune_noisy_rule`, `isolate_compromised_pod`

---

## Detailed Setup Instructions

Follow these step-by-step instructions. Copy-and-paste commands are provided for every operating system and AI client.

---

### Step 1: Infrastructure Setup (If You Do Not Have Docker or Kubernetes Yet)

If you already have Docker and Kubernetes installed and running, you can skip to [Step 2](#step-2-install-falco-triage). 

If you do **not** have Docker, Kubernetes, or the `kind` CLI installed, run the commands for your operating system below:

#### Option A: Windows (PowerShell as Administrator or User)
```powershell
# 1. Install uv (Python package manager)
winget install astral-sh.uv --silent --accept-package-agreements --accept-source-agreements

# 2. Install Docker Desktop
winget install Docker.DockerDesktop --silent --accept-package-agreements --accept-source-agreements

# 3. Install Kubernetes CLI (kubectl)
winget install Kubernetes.kubectl --silent --accept-package-agreements --accept-source-agreements

# 4. Install Kind (Kubernetes-in-Docker)
winget install Kubernetes.kind --silent --accept-package-agreements --accept-source-agreements

# 5. Install Helm (optional)
winget install Helm.Helm --silent --accept-package-agreements --accept-source-agreements
```
> *After installing Docker Desktop on Windows, start **Docker Desktop** from the Start Menu once to initialize the engine.*

#### Option B: macOS (Terminal via Homebrew)
```bash
# 1. Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install uv and Docker Desktop
brew install uv
brew install --cask docker

# 3. Install Kubernetes CLI (kubectl) and Kind
brew install kubectl kind helm
```
> *After installation, open **Docker Desktop** from your Applications folder to initialize the daemon.*

#### Option C: Linux (Ubuntu / Debian / WSL2)
```bash
# 1. Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

# 2. Install Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Activate group changes
newgrp docker

# 3. Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# 4. Install Kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

#### Quick Verification Check
Run this single verification line to confirm your toolchain is operational:
```bash
docker --version && kubectl version --client && kind version && uv --version
```

---

---

### Step 1.1: Installing Falco (Required Pre-Requisite)

> [!IMPORTANT]
> **Falco is a mandatory prerequisite** for live runtime threat monitoring.  
> Falco uses an eBPF driver to monitor Linux kernel system calls in real-time. Follow the baby-step guide below matching your environment:

#### Option A: Installing Falco into Kubernetes / Kind (Recommended)
Follow these 4 baby steps:

**Step 1: Add the Falcosecurity Helm repository**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

**Step 2: Verify your Kubernetes cluster node is reachable**
```bash
kubectl get nodes
```

**Step 3: Deploy Falco with modern eBPF probe and Falcosidekick UI**
```bash
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true
```

**Step 4: Verify the Falco DaemonSet is running**
```bash
kubectl get pods -n falco -o wide
```
*(You should see `falco-*`, `falco-falcosidekick-*`, and `falco-falcosidekick-ui-*` in `Running` state).*

**Step 5: Access the Web UI (Port-Forward)**
```bash
kubectl port-forward -n falco svc/falco-falcosidekick-ui 2802:2802
```
Now visit [http://localhost:2802](http://localhost:2802) in your browser.

---

#### Option B: Installing Falco directly on Linux (Ubuntu / Debian / WSL2)
Follow these baby steps to install the official Falco service:

**Step 1: Install trust key and official repository**
```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update
```

**Step 2: Install linux headers matching your active kernel**
```bash
sudo apt-get install -y linux-headers-$(uname -r)
```

**Step 3: Install the Falco package**
```bash
sudo apt-get install -y falco
```

**Step 4: Choose modern-ebpf driver during setup or configure `/etc/falco/falco.yaml`**
```bash
sudo systemctl enable --now falco
sudo systemctl status falco
```

**Step 5: Verify Falco is processing system calls**
```bash
sudo journalctl -u falco -n 20 --no-pager
```

---

#### Option C: Running Falco as a Standalone Docker Container (Linux Host)
If running on a Linux Docker host:
```bash
docker run -d --name falco \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /etc:/host/etc:ro \
  falcosecurity/falco:latest
```

---

#### How Falco-Triage Connects to Your Falco Installation
Once Falco is installed per above:
1. **Live Falcosidekick UI API**: Alerts are read from port `2802` (`http://localhost:2802/api/v1/events/search`). Port `2801` (Falcosidekick daemon) is only used for `/healthz` checks and lab test-alert POSTs.
2. **Local Falco Event Logs**: If you enable Falco's JSON file output (`json_output: true` plus `file_output` in `falco.yaml`, writing to a path you choose such as `/var/log/falco_events.json`), Falco-Triage can ingest that file directly using `ingest_falco_alerts(source="file", file_path="/var/log/falco_events.json")`.
3. **Local Testing/Sandbox Note**: For Windows/macOS laptops where Linux eBPF drivers cannot attach to the host kernel directly, you can run Falco in a local Kind/Minikube Linux VM, or use `bootstrap_falcosidekick_lab` + `dispatch_test_falco_alert` to simulate real Falco event flows without kernel privileges.

---

### Step 2: Install Falco-Triage

Clone the repository and set up the local virtual environment:

```bash
# 1. Clone the repository
git clone https://github.com/ritvikindupuri/FalcoMCP.git
cd FalcoMCP

# 2. Create an isolated virtual environment with uv
uv venv

# 3. Install the application and all dependencies in editable mode
uv pip install -e ".[dev]"
```

> [!TIP]
> **Directory Path Note**: If you cloned to a different path (e.g. `C:\Users\username\FalcoMCP` or `/home/user/FalcoMCP`), use that directory in the client configuration commands in [Step 4](#step-4-connect-falco-triage-to-your-ai-assistant-all-major-clients) below.

---

### Step 3: Run Pre-Flight Tests

Verify that all 16 unit and integration tests pass cleanly:
```bash
uv run pytest -v
```
You should see:
```text
============================= 16 passed in X.XXs =============================
```

---

### Step 4: Connect Falco-Triage to Your AI Assistant (All Major Clients)

Pick your AI client below. Replace `/path/to/FalcoMCP` (or `C:\\path\\to\\FalcoMCP` on Windows) with the absolute path where you cloned the repository in [Step 2](#step-2-install-falco-triage).

#### 1. Cursor
You can configure Falco-Triage in Cursor via either the UI or a project file:

* **Method A: Project Configuration File (Recommended)**  
  Create or update `.cursor/mcp.json` in your workspace:
  ```json
  {
    "mcpServers": {
      "falco-triage": {
        "command": "uv",
        "args": [
          "--directory",
          "/path/to/FalcoMCP",
          "run",
          "falco-triage"
        ]
      }
    }
  }
  ```
  *(On Windows, use escaped backslashes: `"C:\\Users\\<username>\\FalcoMCP"`)*

* **Method B: Cursor Settings UI**  
  1. Open Cursor and navigate to **Cursor Settings (`Ctrl+,` or `Cmd+,`) > Features > MCP**.
  2. Click **+ Add New MCP Server**.
  3. Enter:
     * **Name**: `falco-triage`
     * **Type**: `command`
     * **Command**: `uv --directory "/path/to/FalcoMCP" run falco-triage`
  4. Click **Save**. The status indicator will turn green.

---

#### 2. Claude Code (CLI `claude`)
If you use Anthropic's **Claude Code** terminal CLI:

```bash
# Terminal command (Linux / macOS / Windows PowerShell):
claude mcp add falco-triage uv -- --directory "/path/to/FalcoMCP" run falco-triage
```

Or add it directly to your `~/.claude.json` configuration file:
```json
{
  "mcpServers": {
    "falco-triage": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/FalcoMCP",
        "run",
        "falco-triage"
      ]
    }
  }
}
```

---

#### 3. Claude Desktop
Add `falco-triage` to your `claude_desktop_config.json`:
* **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
* **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "falco-triage": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/FalcoMCP",
        "run",
        "falco-triage"
      ]
    }
  }
}
```
> *Restart Claude Desktop after editing.*

---

#### 4. Google Antigravity & Gemini CLI
Add `falco-triage` to your global `~/.gemini/config/mcp_config.json`:
* **Windows**: `C:\Users\<username>\.gemini\config\mcp_config.json`
* **Linux / macOS**: `~/.gemini/config/mcp_config.json`

```json
{
  "mcpServers": {
    "falco-triage": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/FalcoMCP",
        "run",
        "falco-triage"
      ]
    }
  }
}
```
> *The companion runbook (`skills/falco-triage/SKILL.md`) and guardrails (`rules/AGENTS.md`) are plain Markdown files; load them however your client supports skills/rules. (A specific Antigravity plugin directory is not verified here.)*

---

#### 5. Windsurf (Codeium)
Add `falco-triage` to your Windsurf MCP configuration file at `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "falco-triage": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/FalcoMCP",
        "run",
        "falco-triage"
      ]
    }
  }
}
```

---

#### 6. VS Code Extensions (Cline / Roo Code / Continue)
For **Cline** or **Roo Code**:
1. Open the **Cline/Roo Code** panel in VS Code.
2. Click the **MCP Servers** icon (plug icon).
3. Click **Configure MCP Servers** (or edit `cline_mcp_settings.json`):
```json
{
  "mcpServers": {
    "falco-triage": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/FalcoMCP",
        "run",
        "falco-triage"
      ]
    }
  }
}
```

---

#### 7. OpenAI Codex & Custom Agent Runtimes
For custom agents using Python or Node.js to spawn MCP processes over stdio:
* **Executable**: `uv`
* **Invocation Arguments**: `["--directory", "/path/to/FalcoMCP", "run", "falco-triage"]`
* **Direct Python Binary Alternative**:
  * Command: `/path/to/FalcoMCP/.venv/bin/python` (or `C:\path\to\FalcoMCP\.venv\Scripts\python.exe` on Windows)
  * Args: `["-m", "falco_triage.server"]`
  * Environment: `{"PYTHONPATH": "/path/to/FalcoMCP/src"}`

> [!NOTE]
> The repository's own `mcp_config.json` uses this direct-Python form but hardcodes the author's Windows paths (`C:\Users\ritvi\.gemini\antigravity\scratch\falco-triage-mcp\...`). If you copy it, replace both the `command` and `PYTHONPATH` values with the paths of your own clone and virtualenv.

---


## How to Use the Plugin (Detailed Step-by-Step Guide)

Falco-Triage is designed so that **no user is ever confused**, regardless of whether you have an enterprise production cluster or are sitting at a laptop with zero infrastructure. 

---

### Quick-Action Prompts (One-Click Copy & Paste)

The moment you ask your assistant *"What is the Falco MCP server and what tools do you have access to?"*, you can immediately launch any of these quick-action prompts:

| Goal / Scenario | Quick-Action Prompt to Copy & Paste | Operational Path |
| :--- | :--- | :--- |
| **Server & Tools Discovery** | `"What is the Falco MCP server and what tools do you have access to?"` | Discovery |
| **Real Test Data with Docker, Falco & K8s** | `"I have Docker, Kubernetes, and Falco installed per the setup guide. Please inspect my cluster, spin up sample Nginx and node-exporter workloads, deploy the Falcosidekick UI forwarder, and dispatch test alerts so I can test rule tuning."` | Path 2 (Testing) |
| **Live Noise Reduction & Clustering** | `"Run ingest_falco_alerts to pull recent alerts from our Falcosidekick deployment at http://localhost:2802, cluster them by rule, and show me the top false positives."` | Path 1 (Production) |
| **Precision Rule Tuning** | `"We are getting hundreds of alerts from '<Rule Name>' on <pod-name> in namespace <namespace>. Correlate the pod and generate a least-privilege Falco structured exception."` | Path 1 (Production) |
| **Immediate Threat Quarantine** | `"Investigate pod <pod-name> in namespace <namespace> using correlate_k8s_workload. If an unexpected interactive shell spawned, generate a zero-trust NetworkPolicy to isolate it immediately."` | Path 1 (Containment) |
| **Docker-Only Lightweight Lab** | `"Launch a fresh Falcosidekick testing lab in Docker using bootstrap_falcosidekick_lab and send a test shell_in_container alert."` | Path 2 (Containers) |
| **Offline Rule Linting & Exception Synthesis** | `"Validate this Falco rule YAML and tell me if the filtercheck fields, operators, and tuple structures conform to CNCF Falco 0.35+ specs."` | Path 1 & 2 (Offline) |

---

### Scenario A: You Already Have Everything Running (Falco, K8s, Falcosidekick)
*Use this in active staging or production environments to eliminate false positives and triage incidents.*

#### Step 1: Ingest Live Production Alerts
In your AI chat (Cursor, Claude Code, Antigravity), type:
> *"Run `ingest_falco_alerts` to pull recent alerts from our Falcosidekick deployment at `http://localhost:2802` and show me the noisiest rules."*

* **What happens**: The agent queries `/api/v1/events/search` (falling back to `/api/v1/events` on 404), groups events by rule and priority, and shows a ranked breakdown of noisy rules with their affected namespaces, pods, process names, and image repositories.

#### Step 2: Correlate with Live Pod Metadata
Pick a noisy rule (e.g. `Write below etc` on pod `node-exporter-4k2ln`) and type:
> *"Inspect the pod `node-exporter-4k2ln` in namespace `monitoring` using `correlate_k8s_workload`."*

* **What happens**: The agent connects to your active cluster via `~/.kube/config`, inspects the pod's `securityContext` (`privileged`, capabilities, host mounts), and shows its owner references (e.g. ReplicaSet or DaemonSet) so you can judge whether it is authorized.

#### Step 3: Synthesize Least-Privilege Exception
Type:
> *"Generate a least-privilege Falco structured exception for this `Write below etc` cluster."*

* **What happens**: The agent calls `generate_falco_exception(strategy="least_privilege")` to generate CNCF Falco 0.35+ YAML scoped by namespace (`monitoring`), process (`node-exporter`), image (`prom/node-exporter`), and file path prefix (`/etc/resolv.conf`).

#### Step 4: Validate and Append to Rules File
Type:
> *"Validate the exception with `validate_falco_rule` and append it to `falco_rules.local.yaml`."*

* **What happens**: The agent checks filtercheck field names, operators, and tuple dimensions, then merges the exception into your local rules file, preserving existing rules and comments. (The append tool itself does not validate, so always validate first.)

#### Step 5: Generate a Quarantine Policy (If Rogue Activity Detected)
If an alert indicates an unauthorized interactive shell (e.g. bash spawned in an external Nginx container), type:
> *"Isolate the pod `web-frontend-x9zlq` in namespace `default` using `generate_pod_isolation_policy`."*

* **What happens**: The agent produces a production `NetworkPolicy` manifest that drops all ingress and egress (except DNS) and provides the copy-and-paste `kubectl apply` command. Nothing is applied automatically; run the command yourself after review.

---

### Scenario B: You Have Falco, Docker, and Kubernetes Installed, but Need Sample Workloads & Alerts to Test ?
*Use this if you installed Falco per [Step 1.1](#step-11-installing-falco-required-pre-requisite) and want to spin up test pods and simulate realistic runtime threats.*

#### The One-Shot Prompt:
Simply copy and paste this prompt into your AI chat:
> *"I have Docker, Kubernetes, and Falco installed per the setup guide. Please inspect my cluster, spin up sample Nginx and node-exporter workloads, deploy the Falcosidekick UI forwarder, and dispatch test alerts so I can test rule tuning."*

*(Or trigger the pre-configured prompt: `spin_up_sample_cluster_and_workloads`)*

#### What the Plugin Autonomously Executes:
1. **Environment Check (`check_lab_environment`)**: The agent checks Docker, Kubernetes connectivity, and the Falcosidekick (`:2801`) and UI (`:2802`) health endpoints.
2. **Falcosidekick Deployment (`deploy_falcosidekick_to_kubernetes`)**:
   * Runs `kubectl apply` with official Falcosidekick and Falcosidekick UI manifests in the `falco` namespace (port-forward `:2801`/`:2802` to reach them from localhost).
3. **Sample Test Pod Provisioning (`deploy_sample_k8s_workloads`)**: Deploys realistic sample workloads to test against:
   * `default/web-frontend`: Nginx web server deployment.
   * `monitoring/node-exporter`: Prometheus node-exporter deployment.
4. **Alert Simulation (`dispatch_test_falco_alert`)**: POSTs a sample Falco event payload to the Falcosidekick daemon (default `http://localhost:2801/`):
   * `write_below_etc`: `node-exporter` writing to `/etc/resolv.conf` (namespace `monitoring`).
   * `shell_in_container`: `bash` inside an `nginx:1.25` container (namespace `default`).
   * `read_sensitive_file`: `datadog-agent` reading `/etc/shadow` (namespace `datadog`).
   * The templates carry fixed sample pod names (e.g. `web-frontend-79f8b4d6b-x9zlq`, `node-exporter-daemon-4k2ln`), not the names of the pods just deployed. Pass `k8s_pod` (and optionally `k8s_ns`, `proc_name`, `container_image`) to point an alert at a real pod.
5. **Live Triage Walkthrough**: The alert appears in the UI (`http://localhost:2802`). The agent queries it back with `ingest_falco_alerts`, inspects the sample pod with `correlate_k8s_workload`, and guides you through tuning your first exception!

---

### Scenario C: You Only Have Docker (Lightweight Container Sandbox)
*Use this if you don't want a Kubernetes cluster and just want a quick, lightweight containerized sandbox.*

#### Step 1: Launch Containers
Type:
> *"Launch a fresh Falcosidekick testing lab in Docker using `bootstrap_falcosidekick_lab`."*

* **What happens**: 
  1. The agent checks Docker. If it is not running, it tries to launch Docker Desktop (Windows default install path only) and asks you to re-run the tool once Docker is up.
  2. Creates a dedicated bridge network (`falco-lab-net`).
  3. Launches official `falcosecurity/falcosidekick` (port 2801) and `falcosecurity/falcosidekick-ui` (port 2802) containers.

#### Step 2: Dispatch Real Alert Payloads
Type:
> *"Send a test `shell_in_container` alert to the daemon."*

* **What happens**: The agent dispatches a real alert payload to `POST http://localhost:2801/`. The alert is viewable at `http://localhost:2802`.

#### Step 3: Triage and Tune
Type:
> *"Ingest the alert from the UI and write a least-privilege exception for it."*

* **What happens**: The agent queries the UI, extracts the process and image, and outputs a validated Falco structured exception.

---

### Scenario D: You Have ZERO Infrastructure Running (Offline "Paste & Tune")
*Use this if you are completely offline, sitting at a laptop without Docker or Kubernetes, and just want to write safe Falco exceptions or lint rules.*

#### 1. Paste & Tune an Alert from Slack / Datadog
Type:
> *"Here is an alert firing in production: `node-exporter opened /etc/resolv.conf for writing in namespace monitoring`. Write a least-privilege exception for it."*

* **What happens**: The agent turns the pasted alert into an `output_fields` sample (e.g. `k8s.ns.name`, `proc.name`, `fd.name`), calls `generate_falco_exception`, and returns the exception YAML plus its validation report, **with no running cluster required**. Fields missing from the sample are filled with placeholders (`default` namespace, `unknown` image, `/var/log` path), so supply them for a precise exception.

#### 2. Pre-Flight Linter & Typo Checker
Type:
> *"Check this custom Falco rule for syntax errors or typos: `- rule: Test; append: true; exceptions: [{name: test, fields: [proc.nme], comps: [=], values: [bash]}]`"*

* **What happens**: The agent runs `validate_falco_rule`, which flags `proc.nme` as a WARNING (it has a known `proc.` prefix, so the result is still `valid: true`) and suggests `proc.name`. Fields without a known prefix are reported as ERRORs.

#### 3. Offline JSON Audit File Analysis
Type:
> *"Analyze this historical Falco audit log file `C:\logs\falco_events.json` and show me the top noisy rules."*

* **What happens**: The agent calls `ingest_falco_alerts(source="file", file_path="...")` and aggregates all false-positive clusters offline.

---
## Testing & Quality Assurance

The test suite includes 16 automated tests covering:
* **Exception Engine**: Multi-field exception construction, least-privilege synthesis (including `fd.name` when file paths are present), and append-then-merge into a YAML file (comment preservation is not asserted).
* **Rule Validator**: Filtercheck dictionary checks, fuzzy typo detection (`proc.cmdlie` $\rightarrow$ `proc.cmdline`), and operator dimension alignment.
* **Alert Ingestion**: Event parsing, JSON log file loading, and alert clustering. (Falcosidekick UI API queries are not tested.)
* **Kubernetes Client**: NetworkPolicy generation (runs without a reachable cluster).
* **Integration**: Server-level calls to 6 of the 13 tools (`check_lab_environment`, `validate_falco_rule`, `generate_falco_exception`, `append_falco_exception_to_file`, `ingest_falco_alerts`, `generate_pod_isolation_policy`) and all 5 prompts. `test_server_check_lab_environment` probes the local Docker/Kubernetes/Falcosidekick endpoints but passes whether or not they are up.

Run the tests anytime:
```bash
uv run pytest -v
```

---

## License

This project is licensed under the Apache 2.0 License. Conforms to CNCF Falco specifications.







