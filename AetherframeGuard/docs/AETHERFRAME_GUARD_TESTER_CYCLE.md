# AetherFrameGuard Tester Cycle

Status: draft cycle for user-reviewed AFG testing

## Goal

Prepare AetherFrameGuard for practical CS2/Windows optimization feedback without promising FPS uplift or silently changing host state.

## First tester profile

Good first testers are technical Windows/CS2 users who can:

- run AFG on a non-critical Windows gaming machine;
- install or point AFG at PresentMon;
- run repeated CS2 practice-map/gameplay measurements;
- report SmartScreen/installer behavior if using an unsigned local build;
- share logs/screenshots without secrets.

Avoid non-technical users who expect a public polished optimizer, guaranteed FPS boost, or silent one-click Windows changes.

## Tester instructions draft

1. Start AetherFrameGuard.
2. Confirm PresentMon status in the UI.
3. Click Measure/Re-test first; do not apply settings yet.
4. Run CS2 in a repeatable practice-map/gameplay scenario.
5. Record Baseline/Latest/Best observed cards.
6. Apply only the clearly listed safe FPS settings if you accept the changes.
7. Relaunch CS2 when AFG says a restart/relaunch is required.
8. Run the same measurement again.
9. Send feedback using the template below.

## Feedback template

- Tester name/handle:
- Windows version:
- GPU/CPU/RAM:
- CS2 resolution/settings summary:
- PresentMon detected: yes/no
- Measurement scenario: menu / lobby / practice map / gameplay
- Baseline avg FPS:
- Baseline 1% low:
- After apply avg FPS:
- After apply 1% low:
- Stability/stutter notes:
- Did UI clearly separate Measure from Apply? yes/no
- Did UI clearly say when CS2 restart/relaunch was required? yes/no
- Did Latest/Best/Baseline feel trustworthy? yes/no
- Any focus theft, console flashes, or unexpected app launches?
- Any Windows security warnings?
- Top 3 confusing parts:
- Top 3 requested fixes:
- Would you use this again? yes/no/why

## Guardrails

- Do not promise a guaranteed FPS increase.
- Do not claim anti-cheat bypass or cheat detection.
- Do not claim malware verdict authority.
- Do not run package delivery or public release steps from this cycle.
- Do not ask testers for credentials, tokens, Steam passwords, or private files.

## NO SAFE NEXT PROMPT conditions

Use `NO SAFE NEXT PROMPT — waiting for user input` if tester names/channels are missing.
Use `NO SAFE NEXT PROMPT — approval gate reached` before sending a build, changing host settings remotely, or publishing instructions publicly.
