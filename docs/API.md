# Dots AI Platform — CLI, HTTP REST, SSE & Operations Reference

This document describes the **implemented** Phase 8A–8C operational interfaces (`src/api/http-server.ts`, `src/cli/main.ts`, `src/runtime/config.ts`, `src/runtime/app.ts`, and `src/scheduler/task-scheduler.ts`).

> **Scope Note**: Web dashboard UI and cron expressions are **planned** for a later milestone and are not yet implemented.

---

## 1. Configuration & Safe Defaults (`src/runtime/config.ts`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DOTS_DB_PATH` | `./data/dots.db` | SQLite database file path (`:memory:` supported for tests). |
| `DOTS_WORKSPACE_ROOT` | `process.cwd()` | Jailed sandbox root directory for file tools. |
| `DOTS_HOST` | `127.0.0.1` | HTTP bind host (loopback default). |
| `DOTS_PORT` | `3847` | HTTP bind port. |
| `DOTS_HOST_SECRET` | Persisted `.dots-host-secret` (`0600`) | 64-char hex HMAC secret used for caller context & task scope attestations. |
| `DOTS_API_TOKEN` | *Required if no `DOTS_TOKENS_JSON`* | Single bearer token (minimum 8 characters). |
| `DOTS_TOKEN_ROLE` | `ADMIN` | Role for `DOTS_API_TOKEN` (`ADMIN`, `MEMBER`, `VIEWER`). |
| `DOTS_TOKEN_PRINCIPAL` | `local-admin` | Principal ID recorded in audit/approval records. |
| `DOTS_TOKEN_SCOPES` | `GLOBAL:default` | Comma-separated scopes (`GLOBAL:default`, `WORKSPACE:<id>`). |
| `DOTS_TOKENS_JSON` | *Optional* | JSON array of `{ token, principalId, role, permittedScopes }`. |
| `DOTS_PROVIDER` | `gemini` if `GEMINI_API_KEY` set, else `mock` | Active model provider (`mock` or `gemini`). |
| `GEMINI_API_KEY` | *Optional* | API key when `DOTS_PROVIDER=gemini`. |
| `GEMINI_MODEL_ID` | `gemini-2.5-flash` | Gemini model identifier. |
| `DOTS_LOG_LEVEL` | `info` | Structured JSON log threshold (`debug`, `info`, `warn`, `error`). |
| `DOTS_MAX_BODY_BYTES` | `1048576` (1 MiB) | Maximum HTTP JSON request body size (`413` if exceeded). |
| `DOTS_SCHEDULER_POLL_MS` | `1000` | Scheduler polling interval in milliseconds (minimum 100 ms). |
| `DOTS_MAX_TASK_BUDGET_USD` | `0.50` | Per-task model cost ceiling in USD. |
| `DOTS_AUTO_APPROVE_TIER2` | `true` | Auto-approve Tier 2 reversible workspace writes; set `false` to require HITL approval. |
| `DOTS_ENABLE_DYNAMIC_REPLAN` | `false` | Enable dynamic replanning on step exhaustion. |
| `DOTS_ENABLE_COMPENSATION` | `true` | Roll back workspace mutations on failed workflows. |
| `DOTS_ENABLE_SCHEDULER` | `true` | Enable persistent scheduler loop in `DotsRuntime.start()`. |
| `DOTS_EMBEDDING_PROVIDER` | `none` | Embedding provider mode (`none`, `local`, `mock`). Default `none` preserves lexical-only operation. |
| `DOTS_EMBEDDING_MODEL_ID` | `onnx-community/all-MiniLM-L6-v2-ONNX` (or `mock-deterministic-v1` for `mock`) | Identifier of sentence embedding model. |
| `DOTS_EMBEDDING_MODEL_REVISION` | `main` | Git revision or commit tag of the embedding model. |
| `DOTS_EMBEDDING_POLL_INTERVAL_MS` | `1000` | Background embedding lifecycle manager queue poll interval in milliseconds. |
| `DOTS_EMBEDDING_LOCAL_MODEL_PATH` | *Optional* | Absolute path to local pre-downloaded model assets for offline `local` provider execution. |

### Memory Embedding Subsystem & Local Model Availability

The platform features an asynchronous, local-first memory embedding subsystem:
- **`none` (Default)**: Memory creation, proposal approval, and retrieval function 100% in deterministic lexical mode without background embedding workers.
- **`local`**: Uses `@huggingface/transformers` with ONNX Runtime CPU execution. By default, `allowRemoteModels = false` to guarantee that no unexpected remote network calls or downloads take place. Models must be pre-downloaded or pointed to via `DOTS_EMBEDDING_LOCAL_MODEL_PATH`.
- **`mock`**: Deterministic offline test provider using pseudo-random hashing for reproducible automated testing without model files.
- **Graceful Drain on Shutdown**: When `DotsRuntime.stop()` is invoked, the embedding worker is stopped and in-flight operations are drained before SQLite is closed, preventing unhandled connection errors.

### Real Local MiniLM Embedding Guide (Phase 4C.9A)

To enable real local semantic memory retrieval powered by `onnx-community/all-MiniLM-L6-v2-ONNX`:

#### 1. Install Optional Runtime
The `@huggingface/transformers` runtime is an optional dependency to keep the core platform lightweight and free of mandatory native binary dependencies:
```bash
npm install --save-optional @huggingface/transformers@^3.8.1
```

#### 2. Model Preparation & Cache Location
Dots enforces strict offline-first execution (`allowRemoteModels = false`), meaning the platform will never initiate unannounced downloads from the Hugging Face Hub during operation.

Model assets must be placed in a local directory outside the repository:
- **Default cache directory**: `~/.cache/dots-models` (Linux/macOS: `$HOME/.cache/dots-models`, Windows: `%USERPROFILE%\.cache\dots-models`)
- **Custom directory**: Configure via `DOTS_EMBEDDING_LOCAL_MODEL_PATH=/path/to/models`

Required model structure:
```text
<cache-dir>/onnx-community/all-MiniLM-L6-v2-ONNX/
├── config.json
├── tokenizer.json
├── tokenizer_config.json
└── onnx/
    ├── model.onnx
    └── model.onnx_data
```

#### 3. Windows and Linux Environment Considerations
- **Operating Systems**: Supported on Linux (x64/arm64) and Windows (x64).
- **Execution Backend**: Uses ONNX Runtime CPU/WASM execution. No GPU drivers or CUDA configurations required.
- **Paths**: On Windows, forward slashes (`/`) or escaped backslashes (`\\`) may be used in `DOTS_EMBEDDING_LOCAL_MODEL_PATH`. Standard home directory expansion resolves correctly across both Windows (`%USERPROFILE%`) and POSIX (`$HOME`).
- **Memory Footprint**: Designed and validated for constrained environments (e.g., 8 GB RAM laptop). Measured memory overhead: ~14 MB heap delta and ~120 MB RSS for ONNX runtime shared libraries.

#### 4. Offline Execution Configuration
To run Dots in local semantic embedding mode:
```bash
export DOTS_EMBEDDING_PROVIDER=local
export DOTS_EMBEDDING_LOCAL_MODEL_PATH=~/.cache/dots-models  # optional if using default location
```
When `DOTS_EMBEDDING_PROVIDER=local`, active memories automatically trigger durable embedding jobs processed in the background by `EmbeddingLifecycleManager`. Memory retrieval automatically uses hybrid scoring combining lexical relevance and cosine similarity.

#### 5. Real-Model Validation Command
To execute the comprehensive real ONNX validation suite:
```bash
DOTS_RUN_REAL_MODEL_TESTS=1 node --test tests/unit/real-local-embedding-validation.test.ts
```

#### 6. Troubleshooting
- **`EmbeddingProviderUnavailableError` (Package not installed)**:
  Run `npm install --save-optional @huggingface/transformers@^3.8.1`.
- **`EmbeddingProviderUnavailableError` (Model not found)**:
  Ensure model assets are present in `~/.cache/dots-models` or the path specified by `DOTS_EMBEDDING_LOCAL_MODEL_PATH`. Because `allowRemoteModels = false` by default, Dots will not automatically fetch missing files over the network.
- **Fallback to Lexical Retrieval**:
  If the embedding provider is disabled (`DOTS_EMBEDDING_PROVIDER=none`) or temporarily unavailable, memory search automatically degrades gracefully to lexical retrieval (`LEXICAL_ONLY` or `LEXICAL_FALLBACK`) without crashing or aborting user queries.

---

## 2. Authentication, Scope Isolation & Roles

All `/api/*` endpoints require authentication (fails closed with `401 Unauthorized` if missing or invalid):
- Header: `Authorization: Bearer <token>` or `X-Dots-Token: <token>`
- Optional Scope Selection (when a token has multiple `permittedScopes`):
  - `X-Dots-Scope: WORKSPACE:<id>` or `X-Dots-Scope: GLOBAL:default`
  - Or `X-Scope-Type` + `X-Scope-Id` headers / `scopeType` + `scopeId` query parameters.
  - Requesting an unpermitted scope fails closed with `403 Forbidden`.

### Role Permissions
| Role | Permissions | Allowed Operations |
| :--- | :--- | :--- |
| `ADMIN` | `READ`, `WRITE`, `DELETE`, `APPROVE` | All read/write ops, approval decisions (`POST /api/approvals/:id/decide`, `POST /api/memories/:id/decide`), memory delete & purge. |
| `MEMBER` | `READ`, `WRITE` | Submit/run/cancel tasks, create/update/archive/export/import memories, manage schedules. Rejected (`403`) on approvals, memory delete, memory purge. |
| `VIEWER` | `READ` | Read tasks, approvals, memories, schedules, and SSE events within permitted scope. Rejected (`403`) on mutations. |

---

## 3. HTTP REST & SSE Endpoints

All JSON responses and error messages are scrubbed of secrets, HMAC attestations (`_scopeAttestation`, `_proof`), and approval tokens (`approvalToken`).

### Health
- `GET /health` (or `GET /api/health`) — Unauthenticated liveness/status summary (`200`).

### Tasks
- `POST /api/tasks` — Submit scoped task `{ goal, metadata?, run? }` (`201`). Set `run: true` to execute to completion/pause before returning.
- `GET /api/tasks` — List tasks in caller's authorized scope (`?status=&limit=&offset=`).
- `GET /api/tasks/:id` — Get task details, steps, scrubbed approvals, audit events, and token usage (`403` on cross-scope access, `404` if missing).
- `GET /api/tasks/:id/audit` — Get scrubbed audit events for a scoped task.
- `POST /api/tasks/:id/run` — Run/resume a non-terminal scoped task.
- `POST /api/tasks/:id/cancel` — Cancel a non-terminal scoped task `{ reason? }`.

### Human Approvals (`ADMIN` only for decisions)
- `GET /api/approvals` — List approval requests in caller's scope (`?decision=PENDING|APPROVED|REJECTED|EXPIRED&limit=`).
- `POST /api/approvals/:id/decide` — Approve or reject `{ decision: "APPROVED" | "REJECTED", resume?: true }` (`403` for `MEMBER`/`VIEWER` or cross-scope).

### Long-Term Memory
- `GET /api/memories` — List memories in caller's scope (`?category=&status=&limit=&offset=`).
- `GET /api/memories/:id` — Get a scoped memory (`404` if not found).
- `POST /api/memories` — Create an active human memory `{ category, key, content, tags?, priority?, metadata? }` (`201`).
- `PATCH /api/memories/:id` — Update memory fields (cannot mutate `status`).
- `POST /api/memories/:id/archive` — Archive an active memory.
- `DELETE /api/memories/:id` — Permanently delete a memory (`ADMIN` only).
- `POST /api/memories/:id/decide` — Approve or reject a `PENDING_APPROVAL` agent proposal `{ decision, reason? }` (`ADMIN` only).
- `GET /api/memories/export` — Export deterministic checksummed bundle (`?category=&includeArchived=`).
- `POST /api/memories/import` — Import bundle `{ bundle, conflictStrategy?: "FAIL" | "SKIP" | "OVERWRITE" }`.
- `POST /api/memories/purge` — Purge archived memories `{ memoryIds? | olderThan?, dryRun?, maxBatchSize? }` (`ADMIN` only).

### Persistent Schedules (`ONE_TIME` & `INTERVAL`)
- `POST /api/schedules` — Create schedule:
  - One-time: `{ name, goal, scheduleType: "ONE_TIME", runAt, missedRunPolicy?: "RUN_ONCE" | "SKIP", maxConsecutiveFailures?, metadata? }`
  - Recurring interval: `{ name, goal, scheduleType: "INTERVAL", intervalMs, startAt?, missedRunPolicy?: "SKIP" | "RUN_ONCE", maxConsecutiveFailures?, metadata? }` (`intervalMs >= 1000`).
- `GET /api/schedules` — List schedules in caller's scope (`?status=&limit=&offset=`).
- `GET /api/schedules/:id` — Get a scoped schedule.
- `GET /api/schedules/:id/occurrences` — List occurrence history (`?limit=&offset=`).
- `POST /api/schedules/:id/pause` — Pause active schedule `{ reason? }`.
- `POST /api/schedules/:id/resume` — Resume paused schedule and reset consecutive failure counter.
- `POST /api/schedules/:id/cancel` — Cancel schedule and any unstarted claimed occurrence.

### Server-Sent Events (SSE)
- `GET /api/events` — Authenticated live stream filtered strictly to the caller's authorized scope (`?taskId=&scheduleId=&type=`).
- `GET /api/tasks/:id/events` — Authenticated live stream for a single scope-verified task.
- Emitted event types: `task.created`, `task.updated`, `approval.requested`, `approval.decided`, `schedule.created`, `schedule.updated`, `occurrence.updated`.

### Standard Error Status Mapping
| Status | Condition |
| :--- | :--- |
| `400` | `ValidationError`, malformed JSON, invalid URL/query parameters |
| `401` | Missing/invalid credentials (`UNAUTHENTICATED`, `MISSING_IDENTITY_INTEGRATION`) |
| `403` | Insufficient role permission, cross-scope access (`TASK_CALLER_SCOPE_MISMATCH`, `SCHEDULE_SCOPE_MISMATCH`, `MemoryScopeViolationError`) |
| `404` | `TaskNotFoundError`, `MemoryNotFoundError`, `ScheduleNotFoundError`, unknown route |
| `409` | `ConcurrencyConflictError`, `MemoryConflictError`, `ScheduleConflictError` |
| `413` | Request body exceeds `DOTS_MAX_BODY_BYTES` |
| `429` | `BudgetExceededError`, `CircuitBreakerError` |
| `500` | Unhandled internal error (stack traces withheld) |

---

## 4. CLI Commands (`src/cli/main.ts`)

Run directly with `node src/cli/main.ts ...` (or `./src/cli/main.ts ...`). Global flags: `--token`, `--scope`, `--server <url>`, `--db <path>`, `--workspace <dir>`, `--json`, `--help`.

- `dots serve [--host 127.0.0.1] [--port 3847]`
- `dots run <goal> [--no-wait]`
- `dots status [taskId] [--status <status>] [--limit <n>]`
- `dots cancel <taskId> [--reason <text>]`
- `dots approvals [--decision PENDING] [--limit <n>]`
- `dots approve <approvalId> [--reject] [--no-resume]`
- `dots memory list|get|create|update|archive|delete|approve|reject|export|import|purge`
- `dots schedule create|list|get|occurrences|pause|resume|cancel`
