# Quality Gates & Acceptance Criteria

> **Document Status**: Approved Baseline (Phase 1)  
> **Testing Philosophy**: Deterministic, Automated, Zero-Flake Quality Gates

---

## 1. Overview & Quality Mandate

In strict adherence to Core Rule 5 (*"Do not claim a feature works until its implementation and relevant tests demonstrate that it works"*), every capability in the Dots AI Platform must satisfy concrete, automated acceptance criteria before being marked complete.

This document defines:
1. **Acceptance Criteria for Phase 1** (Documentation & Architectural Foundation).
2. **Acceptance Criteria for Phase 5 First Vertical Slice** (End-to-End Task Lifecycle).
3. **Comprehensive Testing Matrix** (Unit, Integration, E2E, Crash Recovery, and Security Penetration).

---

## 2. Phase 1 Acceptance Criteria (Architectural Foundation)

| ID | Criterion | Verification Method | Status |
| :---: | :--- | :--- | :---: |
| **AC-P1-01** | **Clean-Slate Workspace Isolation**: Workspace is located strictly within designated scratch directory, completely detached from `OpenDots` and `Nexora-AI`. | Verified via directory inspection and path hierarchy check. | **PASS** |
| **AC-P1-02** | **Complete Deliverables Set**: All 7 required files exist in the specified repository paths (`README.md`, `PRODUCT_VISION.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `ROADMAP.md`, `DECISIONS.md`, `ACCEPTANCE_CRITERIA.md`). | Automated file existence and non-zero byte size check. | **PASS** |
| **AC-P1-03** | **Zero Runtime Prematurity**: No application code, unreviewed dependencies, or container configs created ahead of schedule. | Verified: No `package.json`, `node_modules`, or Python venvs initialized in Phase 1. | **PASS** |
| **AC-P1-04** | **Hardware & Solo Developer Alignment**: Architectural design accounts for Windows 11 host with 8 GB RAM, requiring no paid cloud resources or heavy daemons. | Verified: Architecture specifies in-process SQLite and lightweight single-process runtime (<180 MB footprint). | **PASS** |
| **AC-P1-05** | **Explicit Risk & Decision Surfacing**: Key architectural decisions documented in ADR format with unresolved trade-offs surfaced for user review. | Verified in `docs/DECISIONS.md` section 3. | **PASS** |

---

## 3. Phase 5 Acceptance Criteria: First Complete Vertical Slice

The **First Complete Vertical Slice** represents the foundational end-to-end integration proof.

### The Vertical Slice Scenario:
> A user submits a task: *"Compute SHA-256 hash of test payload and save verification log to scratch directory."*  
> The backend receives and persists the task. The agent formulates a 1-step plan invoking an explicitly allowed tool (`hash_and_save`). The tool executes in the jailed sandbox. The host verification engine asserts that the output file exists and the hash matches the real byte content. An abrupt process restart is simulated (`kill -9` / process exit). Upon reboot, the application queries the database and confirms the task state is `COMPLETED`, the evidence artifact is attached, and the audit trail is 100% intact.

```mermaid
sequenceDiagram
    autonumber
    participant Harness as Automated Test Runner
    participant Host as Dots Application Runtime
    participant DB as SQLite Database
    participant Box as Jailed Sandbox

    Note over Harness,Host: Step 1: Ingestion & Persistence
    Harness->>Host: SubmitTask("Compute SHA-256 hash of payload")
    Host->>DB: INSERT INTO tasks (status="SUBMITTED")
    DB-->>Host: Commit OK (taskId="task-vslice-001")

    Note over Host,Box: Step 2: Planning, Policy & Execution
    Host->>DB: UPDATE tasks SET status="PLANNING"
    Host->>Host: Plan: Step 1 -> Tool: hash_and_save
    Host->>Host: Policy Check: hash_and_save -> Tier 2 (Allowed)
    Host->>Box: Execute hash_and_save(target="payload.txt")
    Box-->>Host: Result: { file: "payload.txt.sha256", hash: "e3b0c44..." }

    Note over Host,DB: Step 3: Independent Host Verification
    Host->>Host: Verifier asserts file exists & checksum matches
    Host->>DB: UPDATE tasks SET status="COMPLETED", evidence={...}

    Note over Harness,Host: Step 4: Crash Simulation
    Harness->>Host: Terminate Process Immediately (Simulated Crash)
    Harness->>Host: Boot Fresh Application Instance

    Note over Harness,DB: Step 5: Cold-Start State Recovery
    Harness->>Host: GetTask("task-vslice-001")
    Host->>DB: SELECT * FROM tasks WHERE id="task-vslice-001"
    DB-->>Host: Status: COMPLETED, Evidence: Intact
    Host-->>Harness: Verify Task matches expected completed state
```

### Detailed Acceptance Criteria for the Vertical Slice:

| ID | Requirement | Measurable Verification Criteria |
| :---: | :--- | :--- |
| **AC-VS-01** | **Task Ingestion & Persistence** | Submitting a task via API/CLI immediately creates a row in `TASKS` table with status `SUBMITTED`, generating a UUIDv4 `id` and ISO UTC timestamp. Querying SQLite immediately reflects this record. |
| **AC-VS-02** | **Strict Policy Enforcement** | Tool invocation is evaluated against the Policy Engine. Only registered tools with valid schema parameters and jailed file paths are approved. |
| **AC-VS-03** | **Jailed Execution** | The tool executes strictly within the configured sandbox directory. Output files are written solely to `sandbox/`. Attempting to target outside paths returns `SECURITY_VIOLATION_PATH_TRAVERSAL`. |
| **AC-VS-04** | **Independent Verification** | The host verifier tests that: (1) `payload.txt.sha256` physically exists on disk, (2) the file size is non-zero, and (3) the hash string matches the actual crypto hash of the test payload. Task fails if verifier does not pass. |
| **AC-VS-05** | **Evidence Attachment** | The task record in `TASKS` is updated to status `COMPLETED` with an immutable `evidence` JSON column containing file path, byte count, calculated hash, and verification timestamp. |
| **AC-VS-06** | **Cold-Start Crash Recovery** | After simulated termination (`process.exit(1)` immediately following verification commit), a newly instantiated backend engine loads `task-vslice-001`. The status must be `COMPLETED`, zero corrupted WAL frames, and full audit logs queryable. |
| **AC-VS-07** | **Audit Trail Completeness** | The `AUDIT_EVENTS` table contains sequentially ordered events: `TASK_CREATED`, `PLAN_GENERATED`, `POLICY_EVALUATED`, `TOOL_EXECUTED`, `EVIDENCE_VERIFIED`, `TASK_COMPLETED`. |

---

## 4. Multi-Layer Testing Strategy

Every subsequent phase must produce automated tests spanning five distinct dimensions:

```
+-----------------------------------------------------------+
|              Security & Penetration Tests                 |
| (Path Traversal, Unauthorized Tool Execution, Secret Leaks)|
+-----------------------------------------------------------+
|                 Chaos & Crash Recovery Tests              |
|        (SIGKILL Mid-Execution, Rehydration Checks)        |
+-----------------------------------------------------------+
|                 End-to-End (E2E) Slice Tests              |
|       (Complete Task Lifecycle from Request to Evidence)  |
+-----------------------------------------------------------+
|                   Integration Tests                       |
|       (FSM + SQLite WAL, Model Gateway + Mock Provider)   |
+-----------------------------------------------------------+
|                      Unit Tests                           |
| (Schema Validation, Token Counters, Path Resolvers, Math) |
+-----------------------------------------------------------+
```

### 4.1 Unit Testing
- **Tool**: Native Node.js test runner (`node:test`, `node:assert`).
- **Focus**: Pure functions, state machine transition validity, schema validators, path canonicalization, secret scrubbing regexes, token math.
- **Speed**: <50 ms per test suite; 100% offline.

### 4.2 Integration Testing
- **Focus**: Inter-module communication between FSM and SQLite repository; Model Gateway with `MockModelProvider`; Tool Registry with Policy Engine.
- **Guarantees**: Real SQLite database in temporary directory; all migrations applied; complete cleanup on teardown.

### 4.3 End-to-End (E2E) Testing
- **Focus**: Complete workflow execution from initial task submission to completion event.
- **Coverage**: Happy paths, approval prompts, and bounded error recovery.

### 4.4 Chaos & Crash Testing
- **Focus**: Simulating process termination during each phase of the FSM (`PLANNING`, `AWAITING_APPROVAL`, `EXECUTING`).
- **Assertions**:
  - Database is never left in a corrupted or locked state.
  - Interrupted tasks are detected during startup recovery and transitioned to `RECOVERING` or `FAILED`.
  - No duplicate tool execution occurs if an idempotency key was committed.

### 4.5 Security & Penetration Testing
- **Test Scenarios**:
  1. `PathTraversalTest`: Model proposes writing to `../../Windows/System32/evil.dll` -> Must be blocked by Policy Engine with audit alert.
  2. `UnregisteredToolTest`: Model invents a non-existent tool `format_drive` -> Must be rejected with `UNKNOWN_TOOL_ERROR`.
  3. `SecretScrubbingTest`: Tool output contains simulated API key `AIzaSyD-fake-key-1234567890abcdef` -> Audit logger must store `[REDACTED_SECRET]`.
  4. `HumanBypassTest`: Agent attempts to execute Tier 4 tool without approval token -> Must be blocked.
