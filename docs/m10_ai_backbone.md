# Milestone 10: AI Analyst Assist Backbone

Date: 2026-04-29

## Implementation Status

**Backend (Rust):** Complete  
**Frontend boundary layer (TypeScript):** Complete  
**Secret storage:** Stronghold-backed (complete)  
**Tests — Rust unit tests:** Complete (5 cases)  
**Tests — TypeScript vitest:** Complete (18 cases, `aiAnalystAssist.test.ts`)  

## Scope

This document defines the backbone implementation for Milestone 10 and the trust
boundaries used by HexHawk AI Analyst Assist.

Implemented backbone areas:
- Backend command module in `src-tauri/src/commands/llm.rs`.
- Provider abstraction for OpenAI, Anthropic, and Ollama — structured so a fourth
  provider (e.g. Anthropic-compatible) can be added by extending the `LlmProvider`
  enum and the `extract_provider_content` / body-building match arms.
- Stronghold-backed secret storage for provider API keys.
- Advisory-only response contract with explicit user approval gating.
- Frontend utility stubs in `HexHawk/src/utils/aiAnalystAssist.ts` for:
  - signal explainer
  - AERIE mode
  - TALON narrate
  - CREST narration
  - Binary diff insight
- All LLM commands registered in `src-tauri/src/main.rs`.

## API Surface

### Tauri commands

| Command | Purpose |
|---|---|
| `llm_query` | Execute an advisory LLM query (all providers) |
| `store_llm_provider_key` | Store a provider API key in Stronghold by provider + alias |
| `clear_llm_provider_key` | Delete a stored key |
| `has_llm_provider_key` | Check whether a key exists without reading it |
| `store_llm_api_key` | Backward-compat wrapper → OpenAI default alias |
| `clear_llm_api_key` | Backward-compat wrapper → OpenAI default alias |
| `has_llm_api_key` | Backward-compat wrapper → OpenAI default alias |

### DTOs

**LlmQueryRequest** (camelCase JSON):
```
provider, action, endpointUrl, modelName, prompt, contextBlocks,
timeoutMs, maxPromptChars, maxContextChars, tokenBudget,
approvalGranted, allowRemoteEndpoint, allowAgentTools, keyAlias
```

**LlmQueryResponse** (camelCase JSON):
```
advisoryOnly, provider, action, modelName, endpointHost, content,
redactionCount, promptChars, contextChars, tokenEstimate,
estimatedCostUsd, warnings
```

`advisoryOnly` is always `true`. No field in the response can mutate GYRE verdict state.

## Trust Boundaries

1. Renderer/UI is untrusted for secret persistence.
2. Backend command boundary is trusted for policy enforcement.
3. External providers are untrusted and can return malformed or unsafe content.
4. AI output is advisory only and cannot directly mutate verdict state.

## Secret Flow

1. The user provides a provider key through a backend command (`store_llm_provider_key`).
2. Backend stores the key in Stronghold-backed storage with a `provider:alias` key.
3. Backend keeps a Stronghold master key in the OS keyring as unlock material.
4. Query execution fetches keys from Stronghold by provider + alias.
5. No raw provider secrets flow through the renderer at any point.
6. Keys never appear in logs (redaction pass runs on all outbound text).

## Policy Enforcement (backend-enforced, non-bypassable)

| Guard | Limit |
|---|---|
| `approvalGranted` | Must be `true` per request — no silent background sends |
| Prompt size | Default 24 000 chars, hard cap 64 000 chars |
| Context size | Default 48 000 chars, hard cap 120 000 chars |
| Context blocks | Max 32 blocks |
| Token budget | Default 4 096, max 16 384; rejected before dispatch if exceeded |
| Timeout | Default 30 s, max 90 s |
| Remote endpoint | Blocked unless `allowRemoteEndpoint=true` per request |
| Tool directives | Blocked unless `allowAgentTools=true` per request |
| Redaction | Applied to all prompt+context before sending to provider |

## Provider Abstraction (OpenAI-first, extensible)

The request body and response parsing are isolated per provider in two match
blocks inside `llm_query_core`:

- **Body construction** — builds the provider-appropriate JSON payload.
- **Content extraction** (`extract_provider_content`) — parses the response.

Adding a new provider requires:
1. Adding a variant to `LlmProvider` enum.
2. Adding a `body` branch in the body-construction match.
3. Adding a parse branch in `extract_provider_content`.
4. Optionally adding a cost-estimate entry in `estimate_cost_usd`.

The HTTP layer is abstracted via `HttpExecutor` trait, enabling full testability
without a network connection.

## AI Can Do

- Produce natural-language explanations and analyst suggestions.
- Summarize and narrate context supplied by approved call sites.
- Return structured advisory text for UI rendering.

## AI Cannot Do

- Directly modify verdict state (GYRE remains sole verdict source).
- Execute tools unless explicitly permitted at request time.
- Bypass approval gating.
- Access provider secrets from renderer-owned storage.
- Send data without explicit per-request `approvalGranted=true`.

## Frontend UI Wiring (TypeScript)

File: `HexHawk/src/utils/aiAnalystAssist.ts`

| Export | Action | Intended call site |
|---|---|---|
| `runSignalExplainer` | `signal_explainer` | GYRE signal detail panel |
| `runAerieMode` | `aerie_mode` | AERIE operator console |
| `runTalonNarrate` | `talon_narrate` | TALON IR decompile view |
| `runCrestNarration` | `crest_narration` | CREST intelligence report export |
| `runBinaryDiffInsight` | `binary_diff_insight` | Binary Diff panel |

All wrappers call `invoke('llm_query', { request })` and propagate errors
faithfully — no silent swallowing.

## Test Coverage

### Rust unit tests (`src-tauri/src/commands/llm.rs`)

| Test | What it proves |
|---|---|
| `key_lookup_failure_returns_error` | Stronghold lookup failure surfaces correctly |
| `provider_timeout_returns_error` | Timeout path returns `ProviderTimeout` |
| `malformed_provider_response_rejected` | Wrong response shape returns `MalformedProviderResponse` |
| `oversized_context_rejected` | Context over limit returns `ContextTooLarge` |
| `token_budget_enforced` | Over-budget request returns `TokenBudgetExceeded` |

### TypeScript vitest (`HexHawk/src/utils/__tests__/aiAnalystAssist.test.ts`)

| Group | Tests |
|---|---|
| `runAnalystAssist` | Calls invoke with correct args; advisoryOnly=true; propagates key lookup failure; propagates provider timeout; propagates malformed response; propagates oversized context; propagates token budget; propagates approval-required; propagates invalid provider config |
| `runSignalExplainer` | Sets action=signal_explainer; does not override other fields |
| `runAerieMode` | Sets action=aerie_mode |
| `runTalonNarrate` | Sets action=talon_narrate |
| `runCrestNarration` | Sets action=crest_narration |
| `runBinaryDiffInsight` | Sets action=binary_diff_insight |
| `advisory isolation` | Response type contains no verdict-mutating fields; content is a plain string |

## Compatibility Notes

Existing command names remain available without breaking changes:
- `llm_query`, `store_llm_api_key`, `clear_llm_api_key`, `has_llm_api_key`

New provider-aware commands added:
- `store_llm_provider_key`, `clear_llm_provider_key`, `has_llm_provider_key`

## Known Residual Risks

- Remote provider data handling remains a data-exfiltration risk when enabled by user
  intent (`allowRemoteEndpoint=true`). Caller must ensure only analyst-approved context
  is included.
- Prompt-level privacy and context hygiene still depend on caller discipline; the
  backend redaction pass is a last-resort guard, not a primary filter.
- Stronghold unlock material bootstrap uses local keyring availability and integrity.
  If the OS keyring is unavailable, key storage operations fail gracefully.

## Next Milestone (M11)

Customer BYOK AI: same `llm_query` command, customer-supplied key per workspace,
Ollama local model support. Key management UI in AERIE settings panel.

