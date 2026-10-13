# Product Vision & Principles: Dots AI Platform

> **Document Status**: Approved Baseline (Phase 1)  
> **Target Audience**: Core Engineering, Architecture Reviewers, Maintainers

---

## 1. Executive Summary & Mission Statement

The **Next-Generation Dots AI Platform** is a reliable, local-first AI agent platform engineered to execute multi-step technical workflows with mathematical determinism, transparent safety boundaries, and provable verification.

Most contemporary "AI agent" frameworks suffer from three systemic flaws:
1. **Unverifiable Optimism**: They assume LLM output is correct, allowing the model to hallucinate success without inspecting real-world side effects.
2. **Fragile Transient State**: State lives in volatile memory. A crash, API timeout, or power interruption destroys the execution graph, requiring restart from zero.
3. **Reckless Execution Privileges**: They grant agents unrestricted shell or filesystem access under the illusion of "full autonomy," posing severe security risks.

**The Dots Mission**: Transform the AI agent from an unpredictable demo into an **auditable, deterministic, and resilient execution engine**. Dots delivers a local-first platform where every action is permissioned, every state transition is persisted, and every completed task is backed by verifiable evidence.

---

## 2. Target Persona & Operating Environment

### Primary User Persona: The Resource-Constrained Solo Engineer / Power User
- **Profile**: A solo developer, technical analyst, or researcher who needs an autonomous digital pair-programmer and workflow automator.
- **Hardware Constraint**: Standard consumer hardware — specifically a Windows 11 laptop with **8 GB RAM** and a standard multi-core CPU.
- **Financial Constraint**: Zero mandatory infrastructure costs. Must run entirely offline or against pay-per-token API endpoints without requiring expensive cloud databases, vector clusters, or always-on Docker daemons.
- **Expectations**: Low memory footprint (<150 MB baseline), fast startup (<2 seconds), zero silent resource leaks, and explicit control over token spend.

---

## 3. Core Functional Pillars

### 1. Provider-Agnostic Intelligence
The runtime must decouple agent reasoning from any single foundation model vendor. Whether using Google Gemini, Anthropic Claude, OpenAI, or local quantized models via Ollama, the interface remains unified. If an external API experiences an outage, routing can switch gracefully to an alternate provider.

### 2. Durable, Transactional State Machine
Every task is governed by a finite state machine (FSM). State transitions, plan steps, intermediate outputs, and human approvals are committed transactionally to an embedded database (SQLite in WAL mode). If the host machine is abruptly powered off during step 4 of a 6-step plan, restarting the application loads the exact state, allowing resumption or clean cancellation without duplicate side effects.

### 3. Policy-Governed Sandboxed Execution
Untrusted AI models never interact directly with the operating system. All actions flow through a **Trusted Host Runtime**. Tools are explicitly typed, cataloged, and assigned to risk tiers. Consequential actions (file writes outside scratch, network requests, system commands) require automated policy evaluation and, where appropriate, explicit human approval.

### 4. Closed-Loop Verification & Tangible Evidence
"I have created the file" is treated as an unverified hypothesis. The agent runtime mandates an independent verification phase:
- Did the target file appear at the target path?
- Does its byte size and cryptographic hash match expectations?
- Did the subprocess exit with code 0?
- Did the response payload pass the JSON schema validation?
A task transition to `COMPLETED` is impossible without verified evidence.

### 5. Bounded Self-Healing & Failure Recovery
When a step fails, the agent does not enter an infinite retry loop that drains user funds. Recovery follows deterministic policies:
- Maximum retry budget per step (default: 2 retries).
- Exponential backoff with jitter for transient network failures.
- Alternative tool fallbacks or plan mutation.
- Graceful degradation: If recovery fails, the system transitions cleanly to `FAILED`, preserves diagnostic artifacts, and notifies the user with actionable context.

### 6. User-Controlled, Auditable Memory
Memory is not an opaque vector dump. Dots separates memory into:
- **Ephemeral Session Context**: Windowed short-term context for active tasks.
- **Explicit Long-Term Knowledge**: User-inspectable, user-editable facts, preferences, and workspace rules stored in structured, readable formats with provenance timestamps. Users can inspect, modify, or erase any memory record at any time.

---

## 4. Explicit Anti-Patterns & Non-Goals

To maintain focus and engineering discipline, the Dots Platform explicitly rejects the following anti-patterns:

| Anti-Pattern | Why Dots Rejects It |
| :--- | :--- |
| **Unbounded Autonomous Loops** | Infinite ReAct loops waste tokens, hallucinate paths, and risk runaway destructive execution. Dots enforces maximum step depth and budget caps. |
| **"God-Mode" Shell Access** | Handing raw bash/PowerShell prompts to an LLM without strict command allowlists and path jailing is an unacceptable security hazard. |
| **UI-First Vanity Prototypes** | Building flashy web dashboards before stabilizing transactional persistence, verification, and sandboxing leads to hollow, unmaintainable software. |
| **Heavy Container/Cluster Dependencies** | Requiring Docker Desktop, Kubernetes, Redis, and vector databases exceeds the 8 GB RAM target budget and complicates local development. |
| **Model Self-Verification** | Asking the same model "Did you do this correctly?" is inherently biased and unscientific. Verification must be performed by deterministic host assertions. |
| **Vendor Lock-in** | Tying agent primitives to provider-specific abstractions (e.g. OpenAI Assistants API or vendor-specific agent frameworks) breaks offline capability and model flexibility. |

---

## 5. Measure of Success

The platform will be considered successful when:
1. **Zero State Loss**: 100% of tasks interrupted midway can be cleanly inspected, resumed, or rolled back upon application restart.
2. **Zero Unauthorized Actions**: 0% of high-consequence operations execute without satisfying explicit permission and approval policies.
3. **Sub-150 MB Idle Footprint**: The application runtime and database engine maintain an operational footprint comfortably within the 8 GB RAM laptop envelope.
4. **Verified Task Completion**: 100% of completed tasks possess verifiable evidence artifacts attached to their audit records.
