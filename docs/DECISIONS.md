# Architecture Decision Records (ADRs)

> **Document Status**: Approved Baseline (Phase 1)  
> **Format**: Lightweight Architecture Decision Records (ADRs) with Context, Decision, Consequences, and Alternatives Considered.

---

## ADR-001: Architectural Pattern — Modular Monolith

- **Status**: **ACCEPTED**
- **Date**: 2026-10-13

### Context & Problem Statement
The platform requires clear separation of concerns (API, state machine, model gateway, policy engine, sandboxed execution, persistence). We need to choose an architectural structure suitable for a solo developer running on an 8 GB RAM Windows laptop.

### Decision
Adopt a **Modular Monolith** pattern organized into isolated, strictly typed modules (`orchestrator`, `storage`, `model-gateway`, `security`, `tools`, `verification`). All modules communicate via in-process TypeScript interfaces and share a transactional SQLite persistence layer.

### Consequences
- **Positive**:
  - Zero network serialization overhead between modules.
  - Trivial local setup; zero container orchestration or service mesh required.
  - Single process memory footprint (<100 MB).
  - Full transactional consistency and atomic database operations across modules.
- **Negative**:
  - Cannot scale individual subsystems independently across multiple physical servers (irrelevant for local-first single-user target).
- **Alternatives Considered**:
  - *Microservices (Docker / HTTP / gRPC)*: Rejected due to severe memory overhead (each container adds 100-300 MB), complex local networking, and unnecessary operational burden on an 8 GB machine.

---

## ADR-002: Language & Runtime — TypeScript on Node.js 24

- **Status**: **ACCEPTED** (Approved by User for Phase 2)
- **Date**: 2026-10-13

### Context & Problem Statement
The runtime environment must support rapid development, strict typing, high I/O throughput, low idle memory consumption (<100 MB), and effortless local execution on the host machine.
System inspection reveals:
- **Node.js v24.21.0** is already installed and verified on the host system.
- **Python** is not currently in the system PATH.

### Decision
Adopt **TypeScript** executing on **Node.js 24** as the primary runtime language. Utilize Node 24's native capabilities:
- Native SQLite support via `node:sqlite` (`DatabaseSync`).
- Native test runner via `node:test`.
- Native cryptographic primitives via `node:crypto`.
- Built-in type stripping / fast modern module execution.

### Consequences
- **Positive**:
  - Leverages existing pre-installed Node.js 24 runtime without requiring new compiler/runtime installations.
  - Zero heavy external dependencies needed for database or testing.
  - Predictable single-threaded event loop with low idle memory (~45 MB).
  - End-to-end type safety across domain models, tool schemas, and API contracts.
  - Unified language if a web interface or CLI is constructed in later phases.
- **Negative**:
  - Standard AI research libraries (PyTorch, HuggingFace) are in Python; however, Dots interacts with models via REST/WebSocket APIs, rendering local PyTorch unnecessary.
- **Alternatives Considered**:
  - *Python 3.12+ (FastAPI + Pydantic + aiosqlite)*: Viable and common in AI, but requires installing Python on the host machine, configuring virtual environments, and typically has a higher memory footprint when AI libraries are loaded. (Flagged in Open Decisions if user prefers Python).
  - *Go / Rust*: Exceptional performance and memory efficiency, but slower development velocity for structured JSON manipulations, dynamic prompt templates, and schema parsing.

---

## ADR-003: Persistence Engine — SQLite with Write-Ahead Logging (WAL)

- **Status**: **ACCEPTED**
- **Date**: 2026-10-13

### Context & Problem Statement
The agent platform requires durable persistence for tasks, steps, tool outputs, audit logs, and memories. State must survive unexpected process termination, crash reboots, and power outages.

### Decision
Use **SQLite** configured with Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) and synchronous normal mode (`PRAGMA synchronous = NORMAL;`). Enforce foreign key constraints (`PRAGMA foreign_keys = ON;`).

### Consequences
- **Positive**:
  - In-process zero-configuration database; zero daemon processes consuming RAM.
  - Complete ACID transaction compliance.
  - WAL mode permits concurrent readers while a write is underway.
  - Single-file database (`dots.db`) makes backups, resets, and inspections trivial.
  - Memory usage is strictly bounded (cache size capped at 16 MB).
- **Negative**:
  - Single-writer concurrency ceiling (entirely sufficient for a solo user running multiple concurrent tasks).
- **Alternatives Considered**:
  - *PostgreSQL*: Excellent relational database, but requires running a dedicated Windows service or Docker container consuming 150-300 MB of idle memory.
  - *In-Memory Store (Redis / RAM)*: Fails durability requirement; state is wiped on crash.
  - *Flat JSON files*: Lacks atomic transactions and foreign keys; prone to file corruption during mid-write crashes.

---

## ADR-004: Model Provider Abstraction — Internal Gateway vs Vendor Frameworks

- **Status**: **ACCEPTED**
- **Date**: 2026-10-13

### Context & Problem Statement
AI applications often couple themselves to proprietary vendor APIs or heavy third-party agent frameworks (e.g. LangChain, LlamaIndex, AutoGen, CrewAI). These frameworks introduce heavy dependency trees, breaking changes, excessive memory bloat, and rigid execution paradigms.

### Decision
Build a lightweight, clean **Model Provider Gateway** implementing a uniform interface (`IModelProvider`):
```typescript
interface IModelProvider {
  name: string;
  generatePlan(prompt: PromptContext, tools: ToolDefinition[]): Promise<PlanResult>;
  generateCompletion(prompt: PromptContext): Promise<CompletionResult>;
}
```
All adapters (Google Gemini, OpenAI, Anthropic, Ollama) will use lightweight direct HTTP/REST calls with standard `fetch()`.

### Consequences
- **Positive**:
  - Complete freedom from framework breaking changes and dependency churn.
  - Tiny runtime footprint (<2 MB code vs 200 MB+ node_modules for heavy frameworks).
  - Effortless addition of new providers or custom local models.
  - Trivial mock provider implementation (`MockModelProvider`) for instant, cost-free automated testing.
- **Negative**:
  - Requires maintaining raw request/response mapping logic for each provider.
- **Alternatives Considered**:
  - *LangChain / LlamaIndex*: Rejected due to massive dependency bloat, high memory overhead, frequent breaking changes, and opaque abstractions.

---

## ADR-005: Security & Sandboxing Strategy — Host-Enforced Jailing

- **Status**: **ACCEPTED**
- **Date**: 2026-10-13

### Context & Problem Statement
AI agents executing local file or command actions pose a severe risk to host operating systems. We must protect the host while keeping hardware overhead within the 8 GB RAM envelope.

### Decision
Implement **Host-Enforced In-Process Jailing & Subprocess Whitelisting**:
1. All file operations must resolve strictly within the designated canonical workspace root (`.../sandbox/`). Any attempt to traverse (`../`) or target absolute system paths is rejected by trusted host code before execution.
2. Tool execution never spawns raw interactive shells (`cmd.exe` or `powershell.exe` with arbitrary command strings).
3. Consequential actions (Tier 3 & 4) trigger human approval workflows with cryptographically signed tokens.
4. Subprocesses run with hard timeouts (15s) and bounded output buffers (512 KB).

### Consequences
- **Positive**:
  - Rock-solid security guarantees enforced in application code.
  - Zero containerization overhead; runs natively and smoothly on Windows without Docker Desktop.
  - Fast execution startup (<5 ms vs 500+ ms for container spawn).
- **Negative**:
  - Does not provide Linux kernel-level cgroup/namespace isolation for arbitrary compiled binaries (mitigated by only allowing whitelisted tools).
- **Alternatives Considered**:
  - *Docker Desktop Containers*: Rejected because Docker Desktop on Windows consumes 2+ GB RAM via WSL2 `vmmem`, which would severely strain an 8 GB laptop.

---

## ADR-006: Orchestration Engine — Deterministic FSM vs Unbounded ReAct

- **Status**: **ACCEPTED**
- **Date**: 2026-10-13

### Context & Problem Statement
Standard ReAct (Reasoning + Acting) loops often suffer from infinite loops, runaway token consumption, hallucinations, and inability to resume after a crash.

### Decision
Implement a **Deterministic Finite State Machine (FSM)** with bounded plan execution:
- Tasks are decomposed into a discrete plan (DAG of maximum 8 steps).
- Every state transition is written to SQLite before action execution.
- Retries are strictly bounded (max 2 retries per step with exponential backoff).
- Transitions to `COMPLETED` require independent evidence verification.

### Consequences
- **Positive**:
  - Eliminates infinite token-draining loops.
  - Perfect state recovery: if the application crashes at step 3, it resumes cleanly at step 3 on restart.
  - Complete visibility into plan progress, status, and failure causes.
- **Negative**:
  - Less "emergent" or free-form behavior than an unbounded loop (this is an intentional design choice for reliability).
- **Alternatives Considered**:
  - *Autonomous Unbounded ReAct*: Rejected due to unpredictability, financial risk, and lack of durability.

---

## ADR-007: Verification Strategy — Independent Host Verification

- **Status**: **ACCEPTED**
- **Date**: 2026-10-13

### Context & Problem Statement
AI agents frequently claim they have completed a task when they have actually hallucinated or encountered silent errors.

### Decision
Enforce **Independent Host Verification**:
- The agent runtime never trusts the model's claim of success.
- Each tool step specifies verification criteria (e.g. `file_exists`, `hash_matches`, `exit_code_zero`, `schema_valid`).
- The host runtime independently executes the verification check. If the check fails, the task transitions to `RECOVERING` or `FAILED`, regardless of what the model stated.

### Consequences
- **Positive**:
  - Guarantees that completed tasks actually produced the expected real-world effects.
  - Provides cryptographic evidence attached to audit logs.
- **Negative**:
  - Requires authoring verification schemas for each tool.
- **Alternatives Considered**:
  - *Model Self-Evaluation ("LLM-as-a-judge")*: Rejected as primary verifier because models can hallucinate their own accuracy and waste unnecessary API tokens.

---

## 3. Approved Decisions & Project Parameters

The following architectural choices have been formally approved by the user for Phase 2:

1. **Runtime**: **TypeScript on Node.js 24** (Zero external runtime install needed, native `node:sqlite`, native `node:test`, lightweight ~50 MB RAM).
2. **Persistence**: **SQLite** via `node:sqlite` (`DatabaseSync`), configured with WAL mode.
3. **Primary Development Model Provider**: **Google Gemini API** as initial real provider with an offline **MockModelProvider** for deterministic, zero-cost automated tests.
4. **User Interface Delivery Mode**: **CLI first**, followed by a lightweight local Web UI in Phase 8.
