/**
 * IntelligenceReport — Structured Analysis Export
 *
 * Renders a complete, printable intelligence report from a BinaryVerdictResult.
 * Supports downloading as JSON or Markdown.
 */

import React, { useState } from 'react';
import type {
  BinaryVerdictResult,
  ReasoningStage,
  Contradiction,
  AlternativeHypothesis,
  BehavioralTag,
} from '../utils/correlationEngine';

// ─── Types ────────────────────────────────────────────────────────────────────

interface Props {
  verdict: BinaryVerdictResult | null;
  binaryPath?: string;
  binarySize?: number;
  architecture?: string;
  fileType?: string;
}

// ─── IOC Extraction ──────────────────────────────────────────────────────────

interface IocEntry {
  type: 'domain' | 'ip' | 'url' | 'filepath' | 'registry' | 'api' | 'hash' | 'string';
  value: string;
  confidence: 'high' | 'medium' | 'low';
  context: string;
}

const URL_RE    = /https?:\/\/[^\s"'<>]{4,}/gi;
const IP_RE     = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|onion)\b/gi;
const PATH_RE   = /(?:[A-Za-z]:\\|\/)[^\s"'<>]{6,}/g;
const REG_RE    = /(?:HKEY_|HKLM|HKCU|HKU)[\\][^\s"'<>]{4,}/gi;

function extractIocs(verdict: BinaryVerdictResult): IocEntry[] {
  const iocs: IocEntry[] = [];
  const seen = new Set<string>();

  function add(ioc: IocEntry) {
    const key = `${ioc.type}:${ioc.value}`;
    if (!seen.has(key)) { seen.add(key); iocs.push(ioc); }
  }

  // Extract from signal findings and evidence
  const texts: Array<{ text: string; context: string }> = [];
  for (const sig of verdict.signals) {
    texts.push({ text: sig.finding, context: `signal:${sig.id}` });
    for (const ev of sig.evidence ?? []) texts.push({ text: ev, context: `evidence:${sig.id}` });
  }

  for (const { text, context } of texts) {
    for (const m of text.matchAll(URL_RE))    add({ type: 'url',      value: m[0], confidence: 'high',   context });
    for (const m of text.matchAll(IP_RE))     add({ type: 'ip',       value: m[0], confidence: 'medium', context });
    for (const m of text.matchAll(DOMAIN_RE)) add({ type: 'domain',   value: m[0], confidence: 'medium', context });
    for (const m of text.matchAll(PATH_RE))   add({ type: 'filepath', value: m[0], confidence: 'low',    context });
    for (const m of text.matchAll(REG_RE))    add({ type: 'registry', value: m[0], confidence: 'high',   context });
  }

  // Extract API names from Mythos/imports signals
  for (const sig of verdict.signals) {
    if ((sig.source as string) === 'mythos' && sig.evidence) {
      for (const ev of sig.evidence) {
        const apiMatch = ev.match(/^import:\s*(.+)$/i);
        if (apiMatch) {
          add({ type: 'api', value: apiMatch[1].trim(), confidence: 'high', context: `mythos:${sig.id}` });
        }
      }
    }
  }

  return iocs;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const THREAT_COLORS: Record<string, string> = {
  clean: '#4dff91',
  suspicious: '#ffcc00',
  packer: '#ff9900',
  dropper: '#ff6633',
  rat: '#ff3333',
  'ransomware-like': '#cc0000',
  'info-stealer': '#ff66cc',
  loader: '#aa88ff',
  'likely-malware': '#ff3300',
  unknown: '#888888',
};

const BEHAVIOR_ICONS: Record<BehavioralTag, string> = {
  'code-injection': '💉',
  'c2-communication': '📡',
  'persistence': '🔒',
  'anti-analysis': '🛡',
  'data-exfiltration': '📤',
  'file-destruction': '🗑',
  'credential-theft': '🔑',
  'code-decryption': '🔓',
  'dynamic-resolution': '🔍',
  'process-execution': '⚡',
  'data-encryption': '🔐',
  'self-contained': '✅',
};

function threatScoreColor(score: number): string {
  if (score >= 80) return '#ff2222';
  if (score >= 60) return '#ff8800';
  if (score >= 40) return '#ffcc00';
  if (score >= 20) return '#88ff00';
  return '#4dff91';
}

function confidenceBadge(confidence: number): string {
  if (confidence >= 80) return 'high';
  if (confidence >= 50) return 'medium';
  return 'low';
}

function severityColor(severity: 'high' | 'medium' | 'low'): string {
  return severity === 'high' ? '#ff4444' : severity === 'medium' ? '#ffaa00' : '#88cc00';
}

function formatMarkdown(verdict: BinaryVerdictResult, meta: Props): string {
  const ts = new Date().toISOString();
  const lines: string[] = [
    `# HexHawk Intelligence Report`,
    ``,
    `**Generated:** ${ts}`,
    `**Binary:** ${meta.binaryPath ?? 'Unknown'}`,
    `**Architecture:** ${meta.architecture ?? 'Unknown'}`,
    `**File Type:** ${meta.fileType ?? 'Unknown'}`,
    `**Size:** ${meta.binarySize ? `${meta.binarySize.toLocaleString()} bytes` : 'Unknown'}`,
    ``,
    `---`,
    ``,
    `## Verdict`,
    ``,
    `| Field | Value |`,
    `|-------|-------|`,
    `| Classification | **${verdict.classification.toUpperCase()}** |`,
    `| Threat Score | ${verdict.threatScore}/100 |`,
    `| Confidence | ${verdict.confidence}% (${confidenceBadge(verdict.confidence)}) |`,
    `| Signals | ${verdict.signalCount} detected |`,
    ``,
    `> ${verdict.summary}`,
    ``,
    `---`,
    ``,
  ];

  if (verdict.behaviors.length > 0) {
    lines.push(`## Behavioral Capabilities`);
    lines.push(``);
    for (const b of verdict.behaviors) {
      lines.push(`- ${BEHAVIOR_ICONS[b] ?? '•'} \`${b}\``);
    }
    lines.push(``);
    lines.push(`---`);
    lines.push(``);
  }

  if (verdict.reasoningChain.length > 0) {
    lines.push(`## Reasoning Chain`);
    lines.push(``);
    for (const stage of verdict.reasoningChain) {
      lines.push(`### Stage ${stage.stage}: ${stage.name} (confidence: ${stage.confidence}%)`);
      lines.push(``);
      for (const f of stage.findings) lines.push(`- ${f}`);
      lines.push(``);
      lines.push(`**Conclusion:** ${stage.conclusion}`);
      lines.push(``);
    }
    lines.push(`---`);
    lines.push(``);
  }

  if (verdict.contradictions.length > 0) {
    lines.push(`## Contradictions`);
    lines.push(``);
    for (const c of verdict.contradictions) {
      lines.push(`### [${c.severity.toUpperCase()}] ${c.id}`);
      lines.push(`- **Observation:** ${c.observation}`);
      lines.push(`- **Conflict:** ${c.conflict}`);
      lines.push(`- **Resolution:** ${c.resolution}`);
      lines.push(``);
    }
    lines.push(`---`);
    lines.push(``);
  }

  if (verdict.alternatives.length > 0) {
    lines.push(`## Alternative Hypotheses`);
    lines.push(``);
    for (const a of verdict.alternatives) {
      lines.push(`### ${a.label} (${a.probability}% probability)`);
      lines.push(`Classification: \`${a.classification}\``);
      lines.push(``);
      lines.push(a.reasoning);
      lines.push(``);
      if (a.requiredEvidence.length > 0) {
        lines.push(`**Would be confirmed by:**`);
        for (const e of a.requiredEvidence) lines.push(`- ${e}`);
      }
      lines.push(``);
    }
    lines.push(`---`);
    lines.push(``);
  }

  if (verdict.signals.length > 0) {
    lines.push(`## Threat Signals`);
    lines.push(``);
    lines.push(`| Source | Finding | Weight |`);
    lines.push(`|--------|---------|--------|`);
    for (const s of verdict.signals) {
      lines.push(`| ${s.source} | ${s.finding} | ${s.weight}/10 |`);
    }
    lines.push(``);
  }

  if (verdict.negativeSignals.length > 0) {
    lines.push(`## Clean Indicators`);
    lines.push(``);
    for (const n of verdict.negativeSignals) {
      lines.push(`- ${n.finding} (−${n.reduction} points)`);
    }
    lines.push(``);
  }

  if (verdict.nextSteps.length > 0) {
    lines.push(`## Recommended Next Steps`);
    lines.push(``);
    for (const step of verdict.nextSteps) {
      lines.push(`- [${step.priority.toUpperCase()}] **${step.action}**`);
      lines.push(`  ${step.rationale}`);
      lines.push(``);
    }
  }

  return lines.join('\n');
}

function downloadText(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ReasoningChain({ stages }: { stages: ReasoningStage[] }) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set([1]));

  const toggle = (stage: number) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(stage) ? next.delete(stage) : next.add(stage);
      return next;
    });
  };

  return (
    <div className="reasoning-chain">
      {stages.map(stage => (
        <div key={stage.stage} className="reasoning-stage">
          <div className="reasoning-stage-header" onClick={() => toggle(stage.stage)}>
            <span className="reasoning-stage-num">Stage {stage.stage}</span>
            <span className="reasoning-stage-name">{stage.name}</span>
            <span className="reasoning-stage-conf" title="Confidence">
              {stage.confidence}%
            </span>
            <span className="reasoning-stage-toggle">
              {expanded.has(stage.stage) ? '▲' : '▼'}
            </span>
          </div>
          {expanded.has(stage.stage) && (
            <div className="reasoning-stage-body">
              <ul className="reasoning-findings">
                {stage.findings.map((f, i) => <li key={i}>{f}</li>)}
              </ul>
              <div className="reasoning-conclusion">→ {stage.conclusion}</div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ContradictionList({ contradictions }: { contradictions: Contradiction[] }) {
  return (
    <div className="contradiction-list">
      {contradictions.map(c => (
        <div key={c.id} className={`contradiction-item contradiction-${c.severity}`}>
          <div className="contradiction-header">
            <span className="contradiction-severity" style={{ color: severityColor(c.severity) }}>
              [{c.severity.toUpperCase()}]
            </span>
            <span className="contradiction-id">{c.id}</span>
          </div>
          <div className="contradiction-observation">
            <span className="contra-label">Observed:</span> {c.observation}
          </div>
          <div className="contradiction-conflict">
            <span className="contra-label">Conflicts with:</span> {c.conflict}
          </div>
          <div className="contradiction-resolution">
            <span className="contra-label">Resolution:</span> {c.resolution}
          </div>
        </div>
      ))}
    </div>
  );
}

function AlternativesList({ alternatives }: { alternatives: AlternativeHypothesis[] }) {
  return (
    <div className="alternatives-list">
      {alternatives.map((a, i) => (
        <div key={i} className="alternative-hypothesis">
          <div className="alt-header">
            <span className="alt-label">{a.label}</span>
            <span className="alt-probability">{a.probability}%</span>
            <span className={`alt-class alt-class-${a.classification}`}>{a.classification}</span>
          </div>
          <div className="alt-reasoning">{a.reasoning}</div>
          {a.requiredEvidence.length > 0 && (
            <div className="alt-evidence">
              <div className="alt-evidence-label">Would be confirmed by:</div>
              <ul>
                {a.requiredEvidence.map((e, j) => <li key={j}>{e}</li>)}
              </ul>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function IntelligenceReport({ verdict, binaryPath, binarySize, architecture, fileType }: Props) {
  const [copied, setCopied] = useState(false);

  if (!verdict) {
    return (
      <div className="intelligence-report-empty">
        <div className="report-empty-icon">📊</div>
        <div className="report-empty-title">Intelligence Report</div>
        <div className="report-empty-subtitle">
          Load a binary and run the analysis pipeline (Inspect → Scan Strings → Disassemble) to generate a report.
        </div>
      </div>
    );
  }

  const verdictColor = THREAT_COLORS[verdict.classification] ?? '#888';
  const scoreColor = threatScoreColor(verdict.threatScore);

  const handleDownloadJSON = () => {
    const report = {
      generatedAt: new Date().toISOString(),
      binary: { path: binaryPath, size: binarySize, architecture, fileType },
      verdict: {
        classification: verdict.classification,
        threatScore: verdict.threatScore,
        confidence: verdict.confidence,
        summary: verdict.summary,
        behaviors: verdict.behaviors,
        signals: verdict.signals,
        negativeSignals: verdict.negativeSignals,
        reasoningChain: verdict.reasoningChain,
        contradictions: verdict.contradictions,
        alternatives: verdict.alternatives,
        nextSteps: verdict.nextSteps,
      },
    };
    downloadText(JSON.stringify(report, null, 2), 'hexhawk-report.json', 'application/json');
  };

  const handleDownloadMarkdown = () => {
    const md = formatMarkdown(verdict, { verdict, binaryPath, binarySize, architecture, fileType });
    downloadText(md, 'hexhawk-report.md', 'text/markdown');
  };

  const handleExportIocs = () => {
    const iocs = extractIocs(verdict);
    const payload = {
      generatedAt: new Date().toISOString(),
      binary: binaryPath?.split(/[\\/]/).pop() ?? 'unknown',
      iocCount: iocs.length,
      iocs,
    };
    downloadText(JSON.stringify(payload, null, 2), 'hexhawk-iocs.json', 'application/json');
  };

  const handleCopy = async () => {
    const md = formatMarkdown(verdict, { verdict, binaryPath, binarySize, architecture, fileType });
    await navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="intelligence-report">
      {/* ── Header ──────────────────────────────────────────────── */}
      <div className="report-header">
        <div className="report-title">Intelligence Report</div>
        <div className="report-actions">
          <button className="report-btn" onClick={handleDownloadJSON}>↓ JSON</button>
          <button className="report-btn" onClick={handleDownloadMarkdown}>↓ Markdown</button>
          <button className="report-btn" onClick={handleExportIocs}>↓ IOCs</button>
          <button className="report-btn" onClick={handleCopy}>
            {copied ? '✓ Copied' : '⎘ Copy'}
          </button>
        </div>
      </div>

      {/* ── Verdict summary ─────────────────────────────────────── */}
      <div className="report-verdict-banner" style={{ borderColor: verdictColor }}>
        <div className="verdict-classification" style={{ color: verdictColor }}>
          {verdict.classification.toUpperCase()}
        </div>
        <div className="verdict-score-block">
          <div className="verdict-score-value" style={{ color: scoreColor }}>
            {verdict.threatScore}
          </div>
          <div className="verdict-score-label">/ 100</div>
        </div>
        <div className="verdict-confidence">
          Confidence: {verdict.confidence}%
          <span className={`confidence-badge confidence-${confidenceBadge(verdict.confidence)}`}>
            {confidenceBadge(verdict.confidence)}
          </span>
        </div>
      </div>
      <div className="report-summary">{verdict.summary}</div>

      {/* ── Binary metadata ─────────────────────────────────────── */}
      {(binaryPath || architecture || fileType) && (
        <div className="report-meta-strip">
          {binaryPath && <span><span className="meta-label">File:</span> {binaryPath.split(/[\\/]/).pop()}</span>}
          {architecture && <span><span className="meta-label">Arch:</span> {architecture}</span>}
          {fileType && <span><span className="meta-label">Type:</span> {fileType}</span>}
          {binarySize && <span><span className="meta-label">Size:</span> {binarySize.toLocaleString()} bytes</span>}
        </div>
      )}

      {/* ── Behavioral tags ──────────────────────────────────────── */}
      {verdict.behaviors.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">Behavioral Capabilities</div>
          <div className="behavior-tags-row">
            {verdict.behaviors.map(b => (
              <span key={b} className={`behavior-tag behavior-tag-${b}`}>
                {BEHAVIOR_ICONS[b] ?? '•'} {b}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Reasoning chain ──────────────────────────────────────── */}
      {verdict.reasoningChain.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">Reasoning Chain</div>
          <ReasoningChain stages={verdict.reasoningChain} />
        </div>
      )}

      {/* ── Contradictions ───────────────────────────────────────── */}
      {verdict.contradictions.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">
            Contradictions
            <span className="section-count">{verdict.contradictions.length}</span>
          </div>
          <ContradictionList contradictions={verdict.contradictions} />
        </div>
      )}

      {/* ── Alternative hypotheses ───────────────────────────────── */}
      {verdict.alternatives.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">
            Alternative Hypotheses
            <span className="section-count">{verdict.alternatives.length}</span>
          </div>
          <AlternativesList alternatives={verdict.alternatives} />
        </div>
      )}

      {/* ── Signals table ────────────────────────────────────────── */}
      {verdict.signals.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">
            Threat Signals
            <span className="section-count">{verdict.signals.length}</span>
          </div>
          <table className="signals-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Finding</th>
                <th>Weight</th>
                <th>Corroborated By</th>
              </tr>
            </thead>
            <tbody>
              {verdict.signals.map((s, i) => (
                <tr key={i}>
                  <td className="signal-source">{s.source}</td>
                  <td>{s.finding}</td>
                  <td className="signal-weight">{s.weight}/10</td>
                  <td className="signal-corr">
                    {s.corroboratedBy.length > 0 ? s.corroboratedBy.join(', ') : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Clean indicators ─────────────────────────────────────── */}
      {verdict.negativeSignals.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">
            Clean Indicators
            <span className="section-count" style={{ color: '#4dff91' }}>{verdict.negativeSignals.length}</span>
          </div>
          <ul className="negative-signals-list">
            {verdict.negativeSignals.map((n, i) => (
              <li key={i}>
                <span className="neg-finding">{n.finding}</span>
                <span className="neg-reduction">−{n.reduction} pts</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ── Next steps ───────────────────────────────────────────── */}
      {verdict.nextSteps.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">Recommended Actions</div>
          <div className="next-steps-list">
            {verdict.nextSteps.map((step, i) => (
              <div key={i} className={`next-step next-step-${step.priority}`}>
                <span className="step-priority">[{step.priority}]</span>
                <div className="step-body">
                  <div className="step-action">{step.action}</div>
                  <div className="step-rationale">{step.rationale}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
