# AetherFrame Reporter Next Prompt Plan

Status: reserved fallback plan

The reporter now includes a narrow non-destructive `NEXT PROMPT CANDIDATE GUIDANCE` section directly in `scripts/aetherframe_factory_cycle.py`, so this fallback plan is not currently active.

If future reporter support evolves, keep it limited to guidance unless explicitly approved:

- remind Hermes to include next mission, evidence, hard rules, missing approvals, validation, stop conditions, and readiness flags;
- do not generate self-executing prompts;
- do not call Hermes recursively;
- do not schedule follow-up runs;
- do not deploy, delete, publish, sign, upload, use credentials, charge money, or deliver packages;
- keep human review as the boundary between cycles.

This file is informational only and is not required by the current commit unless a future run decides to expand reporter behavior.
