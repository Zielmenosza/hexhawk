# Milestone 11 BYOK AI Layer

## Scope
Milestone 11 adds customer-facing Bring Your Own Key (BYOK) controls on top of the Milestone 10 backbone.

Implemented areas:
- Per-provider API key UX for OpenAI, Anthropic, and local Ollama.
- Stronghold-backed secure key storage via backend command boundary.
- Explicit provider and feature enable toggles.
- Per-session token-cap guardrails in frontend request policy.
- Privacy disclosure acknowledgment gate.
- Offline-safe fallback when key/provider is unavailable.
- Explicit user-confirmed request flow (no silent/background model calls).

## Customer-Facing UX
The TALON settings panel now separates:

1. Ordinary settings
- Provider selection.
- Endpoint URL / model.
- Request token budget.
- Session token cap.
- Provider enabled toggles.
- Feature enabled toggles.

2. Secret storage (Stronghold)
- Provider key alias.
- Add key securely.
- Update key securely.
- Remove stored key.
- Test provider/key.
- Stored-key status by provider.

This makes secret management visually distinct from normal preferences.

## Provider Support
- OpenAI: supported, key required.
- Anthropic: supported, key required.
- Local Ollama: supported, key optional.

Provider behavior is enforced before model calls:
- Disabled provider blocks request.
- Disabled feature blocks request.
- Missing/invalid key blocks request for remote providers.
- Session cap overflow blocks request.

## Privacy and Consent
- Users must acknowledge a privacy disclosure before LLM calls.
- Users must explicitly confirm each model request before dispatch.
- No background or automatic LLM invocation is performed.

## Fallback Behavior
Failure or policy block always returns safe advisory fallback:
- Existing TALON output remains primary.
- LLM path never mutates verdict state.
- Missing key, invalid key, disabled provider/feature, and local provider outages degrade gracefully.

## Security Boundary
Secret handling remains in backend Stronghold storage.
Frontend does not own persistent provider secrets.

Commands used:
- store_llm_provider_key
- clear_llm_provider_key
- has_llm_provider_key
- llm_query

## Tests Added
Frontend/byok policy tests were added in:
- HexHawk/src/utils/__tests__/talonLLMPass.test.ts

Coverage includes:
- missing key
- invalid key
- disabled feature
- cap exceeded
- provider disabled
- local Ollama unavailable

## Remaining Risk
1. Provider test uses the same llm_query path; there is no dedicated backend health-check endpoint.
2. Session token cap is enforced client-side for UX/policy flow; backend still enforces per-request budgets but not aggregate session accounting.
3. Key format validation is heuristic and may reject uncommon-but-valid future key shapes.
4. Offline detection for local Ollama is transport-error based and depends on endpoint correctness.

## Deployment Caveats
1. Ensure tauri command capability permissions include provider key commands and llm_query in production builds.
2. Provider defaults are opinionated; enterprise deployments may need policy-managed endpoints/models.
3. If a tenant requires strict network egress policy, pair provider toggles with endpoint allowlisting at deployment level.
4. BYOK UX assumes desktop bridge availability for Stronghold key checks; pure web test harnesses should use inline test keys only.
