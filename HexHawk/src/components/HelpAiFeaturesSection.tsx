import React from 'react';

export function HelpAiFeaturesSection() {
  return (
    <section className="help-ai-features" aria-labelledby="help-ai-features-heading">
      <h4 id="help-ai-features-heading" style={{ color: '#00d4ff' }}>AI features in HexHawk</h4>
      <p>
        HexHawk uses AI in three specific ways. Every AI output shows a source label so you can tell it apart from static analysis and GYRE results.
      </p>
      <ol>
        <li>
          <strong>Pattern recognition (AETHERFRAME).</strong>{' '}
          Matches known reverse-engineering patterns to import calls and constants. It produces labelled observations — not verdicts. It is always available and does not require internet access.
        </li>
        <li>
          <strong>Plain-English summaries.</strong>{' '}
          Generates a short description of what a function appears to do. It uses HexHawk static analysis as its source; the LLM interprets evidence, it does not create evidence. When no LLM is available, HexHawk falls back to static-only mode.
        </li>
        <li>
          <strong>Evidence suggestions (Agent Gate).</strong>{' '}
          Proposes specific analyst notes, such as suggesting a better name for a function. You approve or reject each suggestion. Approved suggestions become notes in your evidence report and are clearly labelled as AI-suggested.
        </li>
      </ol>

      <h5>What AI never does in HexHawk</h5>
      <ul>
        <li>Produce the malware verdict — GYRE does that.</li>
        <li>Add evidence to NEST without your approval.</li>
        <li>Send your binary to the internet; pattern recognition is fully local.</li>
        <li>Override the static analysis.</li>
      </ul>
      <p>If you are unsure whether something is AI or static analysis, look for the source label. Every AI output shows its source.</p>
    </section>
  );
}

export default HelpAiFeaturesSection;
