# Quality Gates & Acceptance Criteria

> **Document Status**: Approved Baseline (Phase 7 Completed)<br/>
> **Testing Philosophy**: Deterministic, Automated, Zero-Flake Quality Gates

---

## 1. Overview & Quality Mandate

In strict adherence to Core Rule 5 (*"Do not claim a feature works until its implementation and relevant tests demonstrate that it works"*), every capability in the Dots AI Platform must satisfy concrete, automated acceptance criteria before being marked complete.

This document defines:
1. **Acceptance Criteria for Phase 1** (Documentation & Architectural Foundation).
2. **Acceptance Criteria for Phase 5 First Vertical Slice** (End-to-End Task Lifecycle).
3. **Phase 7 Quality Gates & Acceptance Matrix** (Long-Term Auditable Memory).
4. **Comprehensive Testing Matrix** (Unit, Integration, E2E, Crash Recovery, and Security Penetration).

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

## 4. Phase 7 Quality Gates & Acceptance Matrix

Phase 7 and Phase 7.5 established the platform's user-controlled, long-term auditable memory subsystem. The following quality matrix defines the formal verification criteria, verification methods, test fixtures, and passing statuses.

### 4.1 Acceptance Matrix

| ID | Criterion & Scope | Verification Method | Exercising Test Files | Status |
| :---: | :--- | :--- | :--- | :---: |
| **AC-P7-01** | **Structured Memory Schema & CRUD Lifecycle**:<br/>Relational SQLite schema with typed columns (`id`, `key`, `category`, `value`, `source`, `confidence`, `scope`, `status`, `metadata`, `timestamp`), indexes, foreign keys, and WAL durability. Complete CRUD operations (`createMemory`, `getMemoryById`, `getMemoryByKey`, `listMemories`, `updateMemory`, `deleteMemory`, `archiveMemory`) with schema validation and confidence bounds ($[0.0, 1.0]$). | Unit & Integration | `tests/unit/memory-repository.test.ts`<br/>`tests/unit/memory-service.test.ts`<br/>`tests/unit/db.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |
| **AC-P7-02** | **Relevance Matching & Context Budgeting**:<br/>Multi-factor deterministic relevance scoring in `RelevanceMatcher` (exact key match, bounded tag overlap, stop-word filtered keyword recall) with stable tie-breaking. Strict token budgeting and priority packing in `MemoryContextBuilder` with atomic context omission in `PromptCompiler` (`maxContextChars` ceiling) preventing prompt overflows without delimiter corruption. | Unit & Integration | `tests/unit/relevance-matcher.test.ts`<br/>`tests/unit/context-builder.test.ts`<br/>`tests/unit/prompt-compiler.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |
| **AC-P7-03** | **Scoped Authorization & Workspace Isolation**:<br/>Cryptographic scope attestation via `MemoryAuthorizer` and `HostMemoryAuthority`. Strict isolation between `GLOBAL` and `WORKSPACE:<id>` scopes. Prevention of cross-scope leakage; cross-workspace operations throw `MemoryScopeViolationError`. | Unit & Integration | `tests/unit/host-authority.test.ts`<br/>`tests/unit/memory-service.test.ts`<br/>`tests/integration/scoped_task_memory.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |
| **AC-P7-04** | **Agent Proposals & Human Approval Gate**:<br/>Autonomous agent tasks submit candidate memories via sandboxed `memory_propose` tool into `PENDING_APPROVAL` status. Proposals are strictly quarantined from prompt injection until approved. `decideProposal` requires human authorization (`APPROVE` or `REJECT`). Strict recursion depth ($\le 5$), key count ($\le 50$), value count ($\le 500$), and size ($\le 16\text{ KiB}$) bounds on proposal metadata. | Unit & Integration | `tests/unit/memory-propose-tool.test.ts`<br/>`tests/unit/memory-service.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |
| **AC-P7-05** | **Canonical RFC 8785 Export, Import & Checksum Verification**:<br/>Deterministic serialization conforming to RFC 8785 JSON Canonicalization Scheme (JCS) in `canonical-json.ts`. Export bundle generation with SHA-256 integrity checksum over canonical items. Pending proposals excluded from export by design. Atomic bundle import (`importMemories`) with SHA-256 validation and configurable conflict strategies (`SKIP`, `OVERWRITE`, `FAIL`). | Unit & Integration | `tests/unit/canonical-json.test.ts`<br/>`tests/unit/memory-provenance-export.test.ts`<br/>`tests/unit/memory-import.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |
| **AC-P7-06** | **Archival & Safe Permanent Purge**:<br/>Archiving transitions memory to `ARCHIVED`, immediately excluding it from context builders and retrieval. `purgeArchivedMemories` permanently deletes only `ARCHIVED` records older than a strict UTC cutoff or by explicit ID list. Rejects purging `ACTIVE` or `PENDING_APPROVAL` records. Cascade `ON DELETE SET NULL` on `memory_task_injections` preserves task execution history. | Unit & Integration | `tests/unit/memory-purge.test.ts`<br/>`tests/unit/memory-service.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |
| **AC-P7-07** | **Tamper-Evident Audit Privacy & Fail-Closed Boundaries**:<br/>Centralized audit sanitization and validation at `AuditRepository` / `audit-policy.ts` boundary. Raw memory keys, content, tags, and arbitrary metadata are stripped from memory lifecycle audit payloads (`MEMORY_*`, `MEMORIES_*`). Strict allowlisting of operational fields and scope strings (`^(?:GLOBAL|WORKSPACE):[a-zA-Z0-9_.-]{1,128}$`). Two-way transactional atomicity: state mutations fail closed and roll back if audit log append fails. | Unit & Integration | `tests/unit/audit-repository.test.ts`<br/>`tests/unit/memory-service.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |
| **AC-P7-08** | **Cold-Start Durability & Retrieval Provenance Persistence**:<br/>Full SQLite WAL mode persistence: memories, proposals, and injection records survive abrupt process shutdown, connection closure, and cold-start reopen from disk. Closed-loop verification of injection tracking in `memory_task_injections` capturing task ID, memory ID, injected prompt snippet, and timestamp. Rehydration verified with zero data corruption. | Integration | `tests/integration/scoped_task_memory.test.ts`<br/>`tests/integration/phase_7_5_memory_lifecycle.test.ts` | **PASS** |

### 4.2 Documented Limitations & Operational Boundaries

1. **Logical Deletion vs. Physical/Forensic Erasure for SQLite On-Disk Records**:
   The `purgeArchivedMemories` routine executes standard SQL `DELETE` operations, removing records from SQLite B-trees and database indexes. In accordance with standard SQLite file architecture and operating system page caches, deleted row data becomes free pages within the SQLite database file and uncheckpointed WAL frames; it is not forensically zero-filled on physical disk sectors. Host environments requiring forensic data sanitization must employ volume-level encryption (e.g., BitLocker) or secure filesystem shredding utilities.

2. **Omission of Pending Proposals from Export Bundles by Design**:
   The `exportMemories` function strictly packages confirmed memories (`ACTIVE` or `ARCHIVED` based on export filters). It deliberately and by design ignores `PENDING_APPROVAL` proposals. Unapproved agent proposals are unconfirmed candidate suggestions and cannot be exported or transferred across platform environments until a human administrator explicitly reviews and approves them.

3. **Strict Scope and Field Retention in Memory Audit Events**:
   The centralized audit privacy policy (`src/storage/audit-policy.ts`) enforces strict property allowlisting and regex value validation on all memory lifecycle audit records (`MEMORY_*` and `MEMORIES_*`). Operational scope fields must strictly match `^(?:GLOBAL|WORKSPACE):[a-zA-Z0-9_.-]{1,128}$`. Any non-conforming scopes, arbitrary metadata properties, raw memory keys, content, or tags are stripped at the audit repository boundary. While this guarantees zero leak of sensitive user memory content into append-only audit trails, it also means audit events record only operational telemetry rather than full historical diffs of memory values.

4. **Automated Test Coverage vs. Formal Third-Party Certification**:
   The platform's passing test suite (316 deterministic unit, integration, and E2E tests) verifies algorithmic and functional compliance with platform architectural requirements and internal security specifications. Passing these automated quality gates confirms platform correctness under specified conditions, but does not constitute formal third-party SOC2, ISO/IEC 27001, Common Criteria, or regulatory certification.

---

## 5. Multi-Layer Testing Strategy

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

### 5.1 Unit Testing
- **Tool**: Native Node.js test runner (`node:test`, `node:assert`).
- **Focus**: Pure functions, state machine transition validity, schema validators, path canonicalization, secret scrubbing regexes, token math.
- **Speed**: <50 ms per test suite; 100% offline.

### 5.2 Integration Testing
- **Focus**: Inter-module communication between FSM and SQLite repository; Model Gateway with `MockModelProvider`; Tool Registry with Policy Engine.
- **Guarantees**: Real SQLite database in temporary directory; all migrations applied; complete cleanup on teardown.

### 5.3 End-to-End (E2E) Testing
- **Focus**: Complete workflow execution from initial task submission to completion event.
- **Coverage**: Happy paths, approval prompts, and bounded error recovery.

### 5.4 Chaos & Crash Testing
- **Focus**: Simulating process termination during each phase of the FSM (`PLANNING`, `AWAITING_APPROVAL`, `EXECUTING`).
- **Assertions**:
  - Database is never left in a corrupted or locked state.
  - Interrupted tasks are detected during startup recovery and transitioned to `RECOVERING` or `FAILED`.
  - No duplicate tool execution occurs if an idempotency key was committed.

### 5.5 Security & Penetration Testing
- **Test Scenarios**:
  1. `PathTraversalTest`: Model proposes writing to `../../Windows/System32/evil.dll` -> Must be blocked by Policy Engine with audit alert.
  2. `UnregisteredToolTest`: Model invents a non-existent tool `format_drive` -> Must be rejected with `UNKNOWN_TOOL_ERROR`.
  3. `SecretScrubbingTest`: Tool output contains simulated API key `AIzaSyD-fake-key-1234567890abcdef` -> Audit logger must store `[REDACTED_SECRET]`.
  4. `HumanBypassTest`: Agent attempts to execute Tier 4 tool without approval token -> Must be blocked.
