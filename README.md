# Next-Generation Dots AI Platform (`dots-platform`)

> **Phase 1 — Architecture and Engineering Foundation**  
> A secure, durable, provider-independent AI agent orchestration platform designed for verifiable task execution and long-term reliability.

---

## 1. Overview & Mission

The **Next-Generation Dots AI Platform** is an independent, general-purpose agent system built to understand natural-language tasks, formulate structured plans, execute operations through strictly permissioned tools, verify outcomes with tangible evidence, recover gracefully from failures, and maintain durable state across restarts.

Unlike chat-only wrappers or unconstrained autonomous script loops, this platform is engineered as a **reliable software system**:
- **Zero Unrestricted Access**: Models never execute arbitrary system commands or operate outside constrained boundaries.
- **Durable Task State**: All steps, plans, tool outputs, and human approvals are stored transactionally and survive process termination.
- **Closed-Loop Verification**: A task is never marked complete based solely on model self-assertion; tangible artifacts and criteria are independently verified.
- **Resource Conscious**: Engineered specifically for a solo developer running on standard hardware (Windows laptop with 8 GB RAM), with low memory overhead (<150 MB baseline) and zero required cloud infrastructure costs.

---

## 2. Core Principles & Non-Negotiables

1. **Independent Clean-Slate Architecture**: This is a brand new project and codebase. It shares no code, history, or identity with legacy projects (e.g., OpenDots or Nexora AI).
2. **Security & Human-in-the-Loop (HITL)**: Consequential, mutating, or network-bound actions require explicit policy evaluation and human approval before execution. Permissions are enforced in trusted host code, never delegated to model discretion.
3. **Provider-Agnostic Abstraction**: Pluggable interfaces support multiple AI providers (OpenAI-compatible APIs, Anthropic, Google Gemini, Ollama/local models) without altering orchestration logic.
4. **Bounded Recovery & Circuit Breakers**: Retries are finite, backoffs are exponential, and failure paths include rollback or compensation routines to prevent token burnout loops.
5. **No Speculative Verification**: Features are claimed working only when backed by passing automated test suites and verifiable outputs.

---

## 3. Repository & Workspace Isolation

This repository is maintained exclusively in an isolated workspace under Antigravity:
```
C:\Users\Dell\.gemini\antigravity\scratch\dots-platform\
├── README.md                          <-- Project overview & entrypoint
└── docs\
    ├── PRODUCT_VISION.md              <-- Mission, user profiles, anti-patterns
    ├── ARCHITECTURE.md                <-- Component topology, data models, state machines
    ├── SECURITY_MODEL.md              <-- Trust boundaries, permission tiers, sandboxing
    ├── ROADMAP.md                     <-- Phased milestone breakdown (Phases 1 - 8)
    ├── DECISIONS.md                   <-- Architecture Decision Records (ADRs)
    └── ACCEPTANCE_CRITERIA.md         <-- Verification contracts & Phase 5 vertical slice
```

It is completely separated from:
- `C:\Users\Dell\OpenDots-Personal-Complete`
- `C:\Users\Dell\Nexora-AI`

---

## 4. Documentation Map

| Document | Purpose & Scope |
| :--- | :--- |
| [PRODUCT_VISION.md](file:///C:/Users/Dell/.gemini/antigravity/scratch/dots-platform/docs/PRODUCT_VISION.md) | Problem statement, user personas, core functional pillars, and explicit non-goals. |
| [ARCHITECTURE.md](file:///C:/Users/Dell/.gemini/antigravity/scratch/dots-platform/docs/ARCHITECTURE.md) | Modular monolith topology, request lifecycles, SQLite schema, state machines, and hardware constraints. |
| [SECURITY_MODEL.md](file:///C:/Users/Dell/.gemini/antigravity/scratch/dots-platform/docs/SECURITY_MODEL.md) | Untrusted model boundary, 5-tier permission policy engine, file jailing, secret safety, and audit logs. |
| [ROADMAP.md](file:///C:/Users/Dell/.gemini/antigravity/scratch/dots-platform/docs/ROADMAP.md) | Step-by-step phased execution from engineering foundation to full multi-step agent runtime. |
| [DECISIONS.md](file:///C:/Users/Dell/.gemini/antigravity/scratch/dots-platform/docs/DECISIONS.md) | Architectural Decision Records (ADRs) evaluating language runtime, database, FSM, and sandboxing. |
| [ACCEPTANCE_CRITERIA.md](file:///C:/Users/Dell/.gemini/antigravity/scratch/dots-platform/docs/ACCEPTANCE_CRITERIA.md) | Rigorous pass/fail criteria for Phase 1 and the end-to-end Phase 5 First Vertical Slice. |

---

## 5. Current Project Status

- **Current Phase**: **Phase 2 — Core Domain, State Machine & SQLite Persistence**
- **Runtime Code Status**: Active implementation under Node.js 24 + TypeScript.
- **Dependencies**: Native standard library (`node:sqlite`, `node:test`, `node:crypto`, `node:fs`).
- **Cloud Readiness**: Configured for GitHub Codespaces (`.devcontainer` with Node.js 24 image).
- **Next Planned Milestone**: **Phase 3 — Provider-Agnostic Model Gateway & Mock/Local Adapter**.
