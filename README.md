# Next-Generation Dots AI Platform (`dots-platform`)

> **Phase 8A–8D Implemented — CLI, HTTP REST/SSE API, Persistent Scheduler & Operational Runtime**  
> A secure, durable, provider-independent AI agent orchestration platform designed for verifiable task execution, human-in-the-loop safety, and long-term reliability.

---

## 1. Overview & Mission

The **Next-Generation Dots AI Platform** is an independent, general-purpose agent system built to understand natural-language tasks, formulate structured plans, execute operations through strictly permissioned tools, verify outcomes with tangible evidence, recover gracefully from failures, and maintain durable state across restarts.

Unlike chat-only wrappers or unconstrained autonomous script loops, this platform is engineered as a **reliable software system**:
- **Zero Unrestricted Access**: Models never execute arbitrary system commands or operate outside constrained boundaries.
- **Durable Task & Schedule State**: All tasks, steps, tool outputs, human approvals, memories, and scheduled occurrences are stored transactionally in SQLite (`node:sqlite`, WAL mode) and survive process termination.
- **Closed-Loop Verification**: A task is never marked complete based solely on model self-assertion; tangible artifacts and criteria are independently verified.
- **Zero Runtime Dependencies**: Built strictly on Node.js 24 built-in modules (`node:sqlite`, `node:http`, `node:crypto`, `node:fs`, `node:test`, `fetch`).

---

## 2. Core Principles & Non-Negotiables

1. **Independent Clean-Slate Architecture**: Built cleanly from scratch with strict module boundaries.
2. **Security & Human-in-the-Loop (HITL)**: Consequential or mutating actions require explicit policy evaluation and human approval (`ADMIN` role) before execution. Scheduled tasks never auto-approve pending human approvals.
3. **Provider-Agnostic Abstraction**: `IModelProvider` supports offline `MockModelProvider` and `GeminiProvider` without changing orchestration logic.
4. **Bounded Recovery & Circuit Breakers**: Retries are finite, backoffs are exponential, and failure paths include compensation routines and automatic schedule pausing on repeated failures.
5. **Scope Isolation & Secret Hygiene**: Every user, task, approval, memory, schedule, and SSE event is isolated to its authorized `GLOBAL` or `WORKSPACE` scope, with automated secret scrubbing across prompts, APIs, logs, and event streams.

---

## 3. Repository Structure

```text
dots-platform/
├── README.md
├── package.json
├── tsconfig.json
├── src/
│   ├── api/http-server.ts           # Native node:http REST API & scoped SSE server
│   ├── cli/main.ts                  # Executable CLI (`dots`) for local & remote usage
│   ├── domain/                      # Entities, TaskStateMachine, typed DomainErrors
│   ├── memory/                      # Relevance matcher, bounded context builder, MemoryService
│   ├── model/                       # IModelProvider, Mock, Gemini, PromptCompiler, SecretScrubber, BudgetTracker
│   ├── orchestrator/                # TaskCoordinator, VariableResolver, CompensationManager
│   ├── runtime/                     # DotsRuntime composition root, config, logger, event bus
│   ├── scheduler/                   # TaskScheduler (ONE_TIME & INTERVAL, 5-point crash recovery)
│   ├── security/                    # HostMemoryAuthority, MemoryAuthorizer, PolicyEngine, ApprovalBroker, TokenIdentityProvider
│   ├── storage/                     # DatabaseManager (SQLite migrations 001–003), Repositories, CrashRecoveryEngine
│   ├── tools/                       # ToolRegistry, sandboxed tools, memory proposal tool
│   └── verification/                # VerificationEngine
├── docs/
│   ├── API.md                       # Implemented CLI, HTTP REST, SSE & operational config reference
│   ├── ARCHITECTURE.md
│   ├── SECURITY_MODEL.md
│   ├── ROADMAP.md
│   ├── DECISIONS.md
│   ├── PRODUCT_VISION.md
│   └── ACCEPTANCE_CRITERIA.md
└── tests/                           # Unit, integration, and E2E test suites (`node:test`)
```

---

## 4. Current Project Status

### Implemented
- **Phases 1–6**: Domain FSM, SQLite WAL persistence, model gateway (`MockModelProvider`, `GeminiProvider`), secret scrubber, budget tracker, 5-tier `PolicyEngine`, sandboxed tools (`calculate`, `text_transform`, `file_read`, `file_write`, `file_list`, `hash_file`), `ApprovalBroker`, `VerificationEngine`, multi-step DAG chaining, dynamic replanning, circuit breakers, compensation, and boot crash recovery.
- **Phases 7 & 7.5**: Scope-isolated, human-controlled long-term memory (`MemoryService`), `memory_propose` agent tool, token-budgeted context injection with provenance tracking, canonical checksummed export/import, and audited archived memory purge.
- **Phase 8A (CLI & HTTP/SSE API)**:
  - Executable CLI (`src/cli/main.ts`, `bin.dots`) supporting `serve`, `run`, `status`, `cancel`, `approvals`, `approve`, `memory ...`, and `schedule ...` in both local SQLite mode and remote `--server` HTTP mode.
  - Zero-dependency `DotsHttpServer` (`src/api/http-server.ts`) with REST endpoints, scoped Server-Sent Events (`GET /api/events`, `GET /api/tasks/:id/events`), `TokenIdentityProvider`, role-based approval restrictions (`ADMIN` required for `APPROVE`/`DELETE`), strict `GLOBAL`/`WORKSPACE` scope isolation, request body size limits (`413`), and secret scrubbing.
- **Phase 8B (Persistent Scheduler)**:
  - `ScheduleRepository` + `TaskScheduler` backed by SQLite migration `003_persistent_scheduler` (`schedules`, `schedule_occurrences`).
  - Supports `ONE_TIME` and recurring `INTERVAL` schedules, pause/resume/cancel, database-enforced duplicate prevention (`UNIQUE(schedule_id, occurrence_key)`, `task_id UNIQUE`, partial unique active-occurrence index), overlap prevention, missed-run policies (`SKIP`, `RUN_ONCE`), bounded consecutive failures with auto-pause, human approval non-bypass, and crash recovery across all 5 interruption points (concurrency = 1).
- **Phase 8C (Operational Readiness)**:
  - `DotsRuntime` composition root (`src/runtime/app.ts`), environment configuration (`src/runtime/config.ts`) with safe localhost defaults (`127.0.0.1:3847`), persisted local host secret (`.dots-host-secret` mode `0600`), structured secret-scrubbed JSON logging (`OperationalLogger`), and graceful startup/shutdown.
- **Phase 3 (Specialized Autonomous Agents)**:
  - **Research Agent** (`research-agent`, `research`): Evidence-based research agent with web search provider abstraction, safe fetching, prompt injection defense, and cross-source synthesis.
  - **Analytics Agent** (`analytics-agent`, `analytics`): Local-first deterministic data analytics agent supporting inline CSV/JSON ingestion, dataset profiling, descriptive statistics, categorical analysis, IQR outlier detection, Pearson correlation ($r$), and time-series trends.
  - **Developer Agent** (`developer-agent`, `developer`): Secure local-first developer agent with 6 core operations (`EXPLAIN`, `ANALYZE`, `DEBUG`, `GENERATE`, `REVIEW`, `TEST_PLAN`), sandboxed workspace file inspection, controlled code generation, approval gates for file writes (Tier 2) and command runs (Tier 3), and strict verification honesty.

### Planned (Not Yet Implemented)
- **Web Dashboard UI** (lightweight browser interface).
- **Cron Expression Scheduling** (only `ONE_TIME` and `INTERVAL` schedules are implemented).

---

## 5. Developer Agent (Phase 3C)

The **Developer Agent** is a secure, local-first coding assistant integrated into the platform's orchestration, security, and tool registry frameworks.

### Capabilities & Canonical IDs
- **Canonical IDs**: `developer-agent`, `developer`
- **Capabilities**: `development`, `code-analysis`, `debugging`, `code-generation`, `general`, `conversation`

### Supported Operations
1. `EXPLAIN` — Structural explanation of source code architecture, logic flow, parameters, and error stack traces.
2. `ANALYZE` — Static code analysis identifying security vulnerabilities (eval, injection, hardcoded secrets), code smells, and unhandled promises.
3. `DEBUG` — Root-cause diagnosis of runtime errors and generation of targeted remediation patches.
4. `GENERATE` — Code generation via configured model providers or fallback scaffolds adhering to constraints and language specifications.
5. `REVIEW` — Multi-pillar code review (Correctness, Security, Maintainability) with actionable verdicts (`APPROVED`, `CHANGES_REQUESTED`, `NEEDS_DISCUSSION`).
6. `TEST_PLAN` — Focused test matrix formulation (Happy path, Edge cases, Error handling, Boundary conditions) and optional sandboxed test execution.

### Security Perimeter & Approval Gates
- **Workspace Confinement**: All file inspections and modifications are strictly jailed within the authorized `workspaceRoot` via `PathValidator`. Path traversal attacks (`../../`) are blocked.
- **Sensitive File Protection**: Strict refusal to inspect credential or environment files (`.env`, `id_rsa`, `*.pem`, `credentials.json`).
- **Prompt Injection Defense**: Comments and strings in inspected source code are sanitized against prompt-injection overrides before evaluation.
- **Human-in-the-Loop Approvals**: Modifying workspace files (Tier 2) and executing commands (Tier 3) pass through the `PolicyEngine` and `ApprovalBroker`. If approval is required and no valid token is provided, the agent records `AWAITING_APPROVAL` status and never mutates state.
- **Verification Honesty**: The agent never claims code was executed or tested unless sandboxed commands actually ran and exited with code 0.

### Example Usage

#### CLI Task Submission
```bash
# Analyze a source file for security vulnerabilities
node src/cli/main.ts --server http://127.0.0.1:3847 run "Analyze security of auth service" \
  --agent developer-agent \
  --param operation=ANALYZE \
  --param files=src/auth.ts

# Propose a test plan
node src/cli/main.ts --server http://127.0.0.1:3847 run "Propose test plan for SessionManager" \
  --agent developer \
  --param operation=TEST_PLAN \
  --param code="class SessionManager { create() { return 'id'; } }"
```

#### Example Report Output (Markdown)
```markdown
# Developer Report: Analyze auth service
**Status**: `COMPLETED` | **Operation**: `ANALYZE` | **Files Inspected**: 1 | **Findings**: 2

## Executive Summary
Developer task processed under operation ANALYZE. Inspected 1 workspace file(s), identified 2 finding(s).

## Code Analysis & Findings
| ID | Severity | Category | Title | Line | Recommendation |
|---|---|---|---|---|---|
| `finding-1` | `CRITICAL` | `SECURITY` | Direct dynamic code execution (eval) | 14 | Replace eval() with safe parsing. |

## Verification & Test Execution
> [!IMPORTANT]
> **Verification Honesty Guarantee**: Code is only certified as passed when verification commands actually ran with exit code 0.
```

### Current Limitations
- Static analysis is rule-based and heuristic; it does not replace comprehensive automated test suites or formal verification.
- The Developer Agent does not perform autonomous deployments, terminal shell bypasses, or production infrastructure modifications.
- Without a configured model provider (`GeminiProvider`), code generation falls back to deterministic scaffolds.

---

## 5. Quick Start (Local Backend & CLI)

Requires **Node.js 24+**.

```bash
# Configure an API token (min 8 chars) and optional workspace scope
export DOTS_API_TOKEN="dev-admin-token-123456"

# Start the local HTTP + SSE + Persistent Scheduler server (defaults to offline Mock provider unless GEMINI_API_KEY is set)
node src/cli/main.ts serve

# Or submit and inspect tasks via CLI (local SQLite or --server http://127.0.0.1:3847)
node src/cli/main.ts --server http://127.0.0.1:3847 run "Calculate 6 * 7"
node src/cli/main.ts --server http://127.0.0.1:3847 status
node src/cli/main.ts --server http://127.0.0.1:3847 approvals --decision PENDING
```

See [docs/API.md](file:///workspaces/dots-platform/docs/API.md) for all HTTP endpoints, SSE streams, CLI commands, and environment variables.

---

## 6. Documentation Map

| Document | Purpose & Scope |
| :--- | :--- |
| [API.md](file:///workspaces/dots-platform/docs/API.md) | Implemented HTTP REST endpoints, SSE streams, CLI commands, auth/roles, and configuration. |
| [PRODUCT_VISION.md](file:///workspaces/dots-platform/docs/PRODUCT_VISION.md) | Problem statement, user personas, core functional pillars, and explicit non-goals. |
| [ARCHITECTURE.md](file:///workspaces/dots-platform/docs/ARCHITECTURE.md) | Modular monolith topology, request lifecycles, SQLite schema, state machines, and scheduler durability. |
| [SECURITY_MODEL.md](file:///workspaces/dots-platform/docs/SECURITY_MODEL.md) | Untrusted model boundary, 5-tier permission policy engine, file jailing, secret safety, and audit logs. |
| [ROADMAP.md](file:///workspaces/dots-platform/docs/ROADMAP.md) | Phased execution status across Phases 1–8. |
| [DECISIONS.md](file:///workspaces/dots-platform/docs/DECISIONS.md) | Architectural Decision Records (ADRs) evaluating language runtime, database, FSM, and sandboxing. |
| [ACCEPTANCE_CRITERIA.md](file:///workspaces/dots-platform/docs/ACCEPTANCE_CRITERIA.md) | Rigorous pass/fail verification contracts across completed phases. |
