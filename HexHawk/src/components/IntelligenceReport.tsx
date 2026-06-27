/**
 * IntelligenceReport — Structured Analysis Export
 *
 * Renders a complete, printable intelligence report from a BinaryVerdictResult.
 * Supports downloading as JSON or Markdown.
 */

import React, { useEffect, useMemo, useState } from 'react';
import type {
  BinaryVerdictResult,
  ReasoningStage,
  Contradiction,
  AlternativeHypothesis,
  BehavioralTag,
} from '../utils/correlationEngine';
import {
  describeHexHawkReportRefinement,
  refineHexHawkReportMarkdown,
} from '../utils/aetherframeReportRefinementAdapter';

// ─── Types ────────────────────────────────────────────────────────────────────

interface Props {
  verdict: BinaryVerdictResult | null;
  binaryPath?: string;
  binarySize?: number;
  architecture?: string;
  fileType?: string;
  aiContributions?: AiContributions;
}

export interface ReportSnapshot {
  id: string;
  generatedAt: string;
  binaryPath?: string;
  binaryName: string;
  binarySize?: number;
  architecture?: string;
  fileType?: string;
  classification: BinaryVerdictResult['classification'];
  threatScore: number;
  confidence: number;
  signalCount: number;
  iocCount: number;
  behaviors: BehavioralTag[];
  summary: string;
  notes?: string;
}

export interface ReportComparison {
  classificationChanged: boolean;
  threatScoreDelta: number;
  confidenceDelta: number;
  signalCountDelta: number;
  iocCountDelta: number;
  behaviorsAdded: BehavioralTag[];
  behaviorsRemoved: BehavioralTag[];
}

export const REPORT_SNAPSHOTS_STORAGE_KEY = 'hexhawk.reportSnapshots';
const MAX_REPORT_SNAPSHOTS = 12;

export type AiContributionSection = {
  section: 'function_summary' | 'pattern_observations' | 'analyst_accepted_suggestions';
  source: 'aetherframe-llm' | 'aetherframe-static-only' | 'aetherframe-static' | 'agent-gate-approved';
  count?: number;
  advisory_only: true;
  gyre_is_sole_verdict_authority: true;
};

export interface AiContributions {
  present: boolean;
  sections: AiContributionSection[];
  ai_did_not_affect_verdict: true;
  gyre_is_sole_verdict_authority: true;
}

export const EMPTY_AI_CONTRIBUTIONS: AiContributions = {
  present: false,
  sections: [],
  ai_did_not_affect_verdict: true,
  gyre_is_sole_verdict_authority: true,
};

function normalizeAiContributions(ai?: AiContributions): AiContributions {
  if (!ai || !ai.present || ai.sections.length === 0) {
    return EMPTY_AI_CONTRIBUTIONS;
  }
  return {
    present: true,
    sections: ai.sections.map(section => ({
      ...section,
      advisory_only: true,
      gyre_is_sole_verdict_authority: true,
    })),
    ai_did_not_affect_verdict: true,
    gyre_is_sole_verdict_authority: true,
  };
}

function formatAiSectionLabel(section: AiContributionSection['section']): string {
  switch (section) {
    case 'function_summary': return 'Function summary';
    case 'pattern_observations': return 'Pattern observations';
    case 'analyst_accepted_suggestions': return 'Accepted suggestions';
    default: return section;
  }
}

function formatAiSourceLabel(source: AiContributionSection['source']): string {
  switch (source) {
    case 'aetherframe-llm': return 'AETHERFRAME LLM';
    case 'aetherframe-static-only': return 'AETHERFRAME static-only';
    case 'aetherframe-static': return 'AETHERFRAME static';
    case 'agent-gate-approved': return 'Analyst-approved';
    default: return source;
  }
}

function formatAiRole(section: AiContributionSection['section']): string {
  switch (section) {
    case 'function_summary': return 'Interpretation';
    case 'pattern_observations': return 'Pattern match';
    case 'analyst_accepted_suggestions': return 'Notes only';
    default: return 'Advisory';
  }
}

function appendAiContributionsMarkdown(lines: string[], ai: AiContributions): void {
  lines.push('---');
  lines.push('');
  lines.push('## AI Contributions (advisory only)');
  lines.push('');
  lines.push('The following section records whether this report embedded AI-generated interpretations. These are advisory analysis only.');
  lines.push('GYRE is the sole verdict authority. AI did not affect the GYRE verdict or NEST evidence convergence.');
  lines.push('');
  if (!ai.present || ai.sections.length === 0) {
    lines.push('No AI observations were generated for this analysis.');
    lines.push('');
    return;
  }
  lines.push('| Section | Source | Role |');
  lines.push('|---------|--------|------|');
  for (const section of ai.sections) {
    const count = typeof section.count === 'number' ? ` (${section.count})` : '';
    lines.push(`| ${formatAiSectionLabel(section.section)}${count} | ${formatAiSourceLabel(section.source)} | ${formatAiRole(section.section)} |`);
  }
  lines.push('');
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

export type IntelligenceReportMarkdownOptions = {
  aetherframe?: {
    enabled: boolean;
    reason?: string;
  };
  aiContributions?: AiContributions;
};

export function formatMarkdown(
  verdict: BinaryVerdictResult,
  meta: Props,
  options: IntelligenceReportMarkdownOptions = {},
): string {
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

  appendAiContributionsMarkdown(lines, normalizeAiContributions(options.aiContributions ?? meta.aiContributions));

  const baseMarkdown = lines.join('\n');
  return refineHexHawkReportMarkdown({
    markdown: baseMarkdown,
    verdict: {
      classification: verdict.classification,
      threatScore: verdict.threatScore,
      confidence: verdict.confidence,
      sourceEngine: 'gyre',
    },
    policy: options.aetherframe ?? { enabled: true, reason: 'report-markdown-export' },
  }).markdown;
}

function binaryNameFromPath(binaryPath?: string): string {
  return binaryPath?.split(/[\\/]/).pop() ?? 'unknown';
}

export function createReportSnapshot(verdict: BinaryVerdictResult, meta: Props): ReportSnapshot {
  return {
    id: `${Date.now()}-${verdict.classification}-${verdict.threatScore}-${verdict.signalCount}`,
    generatedAt: new Date().toISOString(),
    binaryPath: meta.binaryPath,
    binaryName: binaryNameFromPath(meta.binaryPath),
    binarySize: meta.binarySize,
    architecture: meta.architecture,
    fileType: meta.fileType,
    classification: verdict.classification,
    threatScore: verdict.threatScore,
    confidence: verdict.confidence,
    signalCount: verdict.signalCount,
    iocCount: extractIocs(verdict).length,
    behaviors: verdict.behaviors,
    summary: verdict.summary,
  };
}

export function compareReportSnapshots(current: ReportSnapshot, baseline: ReportSnapshot): ReportComparison {
  const currentBehaviors = new Set(current.behaviors);
  const baselineBehaviors = new Set(baseline.behaviors);

  return {
    classificationChanged: current.classification !== baseline.classification,
    threatScoreDelta: current.threatScore - baseline.threatScore,
    confidenceDelta: current.confidence - baseline.confidence,
    signalCountDelta: current.signalCount - baseline.signalCount,
    iocCountDelta: current.iocCount - baseline.iocCount,
    behaviorsAdded: current.behaviors.filter(behavior => !baselineBehaviors.has(behavior)),
    behaviorsRemoved: baseline.behaviors.filter(behavior => !currentBehaviors.has(behavior)),
  };
}

function loadStoredSnapshots(): ReportSnapshot[] {
  if (typeof window === 'undefined') {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(REPORT_SNAPSHOTS_STORAGE_KEY);
    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw) as ReportSnapshot[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistSnapshots(snapshots: ReportSnapshot[]): void {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(REPORT_SNAPSHOTS_STORAGE_KEY, JSON.stringify(snapshots));
  } catch {
    // Ignore local persistence failures so reporting remains usable.
  }
}

function formatDelta(value: number): string {
  if (value > 0) {
    return `+${value}`;
  }
  return `${value}`;
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

export function formatDiffMarkdown(
  comparison: ReportComparison,
  current: ReportSnapshot,
  baseline: ReportSnapshot,
): string {
  const lines: string[] = [];
  lines.push(`# Snapshot Comparison — ${current.binaryName}`);
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('## Baseline Snapshot');
  lines.push(`- **Saved:** ${new Date(baseline.generatedAt).toLocaleString()}`);
  lines.push(`- **Classification:** ${baseline.classification}`);
  lines.push(`- **Threat Score:** ${baseline.threatScore}`);
  lines.push(`- **Confidence:** ${baseline.confidence}%`);
  if (baseline.notes) lines.push(`- **Analyst Notes:** ${baseline.notes}`);
  lines.push('');
  lines.push('## Current Report');
  lines.push(`- **Generated:** ${new Date(current.generatedAt).toLocaleString()}`);
  lines.push(`- **Classification:** ${current.classification}`);
  lines.push(`- **Threat Score:** ${current.threatScore}`);
  lines.push(`- **Confidence:** ${current.confidence}%`);
  if (current.notes) lines.push(`- **Analyst Notes:** ${current.notes}`);
  lines.push('');
  lines.push('## Delta');
  lines.push(`| Metric | Baseline | Current | Delta |`);
  lines.push(`|--------|----------|---------|-------|`);
  lines.push(`| Threat Score | ${baseline.threatScore} | ${current.threatScore} | ${formatDelta(comparison.threatScoreDelta)} |`);
  lines.push(`| Confidence | ${baseline.confidence}% | ${current.confidence}% | ${formatDelta(comparison.confidenceDelta)} |`);
  lines.push(`| Signals | ${baseline.signalCount} | ${current.signalCount} | ${formatDelta(comparison.signalCountDelta)} |`);
  lines.push(`| IOCs | ${baseline.iocCount} | ${current.iocCount} | ${formatDelta(comparison.iocCountDelta)} |`);
  lines.push('');
  if (comparison.classificationChanged) {
    lines.push(`**Classification drift:** ${baseline.classification} → ${current.classification}`);
    lines.push('');
  }
  if (comparison.behaviorsAdded.length > 0) {
    lines.push(`**Behaviors added:** ${comparison.behaviorsAdded.join(', ')}`);
    lines.push('');
  }
  if (comparison.behaviorsRemoved.length > 0) {
    lines.push(`**Behaviors removed:** ${comparison.behaviorsRemoved.join(', ')}`);
    lines.push('');
  }
  return lines.join('\n');
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

export function IntelligenceReport({ verdict, binaryPath, binarySize, architecture, fileType, aiContributions }: Props) {
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);
  const [aetherframeMarkdownEnabled, setAetherframeMarkdownEnabled] = useState(true);
  const [snapshots, setSnapshots] = useState<ReportSnapshot[]>(() => loadStoredSnapshots());
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>('');

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

  const reportAiContributions = normalizeAiContributions(aiContributions);
  const verdictColor = THREAT_COLORS[verdict.classification] ?? '#888';
  const scoreColor = threatScoreColor(verdict.threatScore);
  const currentSnapshot = useMemo(
    () => createReportSnapshot(verdict, { verdict, binaryPath, binarySize, architecture, fileType }),
    [verdict, binaryPath, binarySize, architecture, fileType],
  );
  const relevantSnapshots = useMemo(
    () => snapshots.filter(snapshot => snapshot.binaryPath === binaryPath || snapshot.binaryName === currentSnapshot.binaryName),
    [snapshots, binaryPath, currentSnapshot.binaryName],
  );
  const selectedSnapshot = useMemo(
    () => relevantSnapshots.find(snapshot => snapshot.id === selectedSnapshotId) ?? relevantSnapshots[0] ?? null,
    [relevantSnapshots, selectedSnapshotId],
  );
  const comparison = useMemo(
    () => (selectedSnapshot ? compareReportSnapshots(currentSnapshot, selectedSnapshot) : null),
    [currentSnapshot, selectedSnapshot],
  );

  useEffect(() => {
    if (!selectedSnapshotId && relevantSnapshots.length > 0) {
      setSelectedSnapshotId(relevantSnapshots[0].id);
    }
  }, [relevantSnapshots, selectedSnapshotId]);

  useEffect(() => {
    persistSnapshots(snapshots);
  }, [snapshots]);

  const handleDownloadJSON = () => {
    const generatedAt = new Date().toISOString();
    const verdictSnapshotId = `gyre-${generatedAt}-${verdict.classification}-${verdict.threatScore}`;
    const aetherframeReportLineage = describeHexHawkReportRefinement(markdownExportOptions.aetherframe);
    const report = {
      generatedAt,
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
      final_verdict_snapshot: {
        verdict_snapshot_id: verdictSnapshotId,
        source_engine: 'gyre',
        gyre_is_sole_verdict_source: true,
        gyre_schema_version: '1.0.0',
        classification: verdict.classification,
        confidence: verdict.confidence,
        threat_score: verdict.threatScore,
        summary: verdict.summary,
        signal_count: verdict.signalCount,
        nest_linkage: {
          nest_enrichment_applied: false,
          gyre_is_sole_verdict_source: true,
          note: 'Report export preserves GYRE authority. Typed NEST evidence bundles are exported only by the NEST evidence path after a real native NEST completion.',
        },
      },
      nest_evidence_bundle: null,
      nestEvidenceBundle: null,
      nest_evidence_bundle_status: 'not_embedded_in_report_export; use NEST evidence export after real native NEST completion',
      ai_contributions: reportAiContributions,
      authority_doctrine: {
        gyre_is_sole_verdict_source: true,
        nest_role: 'evidence-orchestration-only',
        aetherframe_role: 'bounded-uplift-lineage-only',
        nexus_role: 'non-authoritative-assistant-layer',
      },
      aetherframe_report_packaging: {
        enabled: aetherframeReportLineage.applied,
        adapter: aetherframeReportLineage.adapter,
        pass_id: aetherframeReportLineage.passId,
        category: aetherframeReportLineage.category,
        mutation_scope: aetherframeReportLineage.mutationScope,
        deterministic: aetherframeReportLineage.deterministic,
        policy_reason: aetherframeReportLineage.policyReason,
        protected_verdict_fields: {
          classification: verdict.classification,
          threat_score: verdict.threatScore,
          confidence: verdict.confidence,
          source_engine: 'gyre',
          gyre_is_sole_verdict_source: true,
        },
        blocked_mutations: aetherframeReportLineage.blockedMutations,
        proof_limits: aetherframeReportLineage.proofLimits,
        note: aetherframeReportLineage.applied
          ? 'AETHERFRAME packages report lineage and authority disclosure only; it does not change verdict truth or NEST evidence selection.'
          : 'AETHERFRAME report packaging is disabled for this export policy; verdict truth and report body remain GYRE/NEST-derived.',
      },
    };
    downloadText(JSON.stringify(report, null, 2), 'hexhawk-report.json', 'application/json');
  };

  const markdownExportOptions: IntelligenceReportMarkdownOptions = {
    aetherframe: {
      enabled: aetherframeMarkdownEnabled,
      reason: aetherframeMarkdownEnabled ? 'report-panel-analyst-enabled' : 'high-assurance-report-panel-disabled',
    },
    aiContributions: reportAiContributions,
  };

  const handleDownloadMarkdown = () => {
    const md = formatMarkdown(verdict, { verdict, binaryPath, binarySize, architecture, fileType }, markdownExportOptions);
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
    const md = formatMarkdown(verdict, { verdict, binaryPath, binarySize, architecture, fileType }, markdownExportOptions);
    await navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSaveSnapshot = () => {
    const snapshot = createReportSnapshot(verdict, { verdict, binaryPath, binarySize, architecture, fileType });
    setSnapshots(prev => {
      const filtered = prev.filter(existing => !(
        existing.binaryPath === snapshot.binaryPath
        && existing.classification === snapshot.classification
        && existing.threatScore === snapshot.threatScore
        && existing.confidence === snapshot.confidence
        && existing.signalCount === snapshot.signalCount
        && existing.iocCount === snapshot.iocCount
        && existing.summary === snapshot.summary
      ));
      return [snapshot, ...filtered].slice(0, MAX_REPORT_SNAPSHOTS);
    });
    setSelectedSnapshotId(snapshot.id);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleUpdateNote = (id: string, notes: string) => {
    setSnapshots(prev => prev.map(s => s.id === id ? { ...s, notes } : s));
  };

  const handleExportDiffMarkdown = () => {
    if (!comparison || !selectedSnapshot) return;
    const md = formatDiffMarkdown(comparison, currentSnapshot, selectedSnapshot);
    const safeName = currentSnapshot.binaryName.replace(/[^a-zA-Z0-9_-]/g, '_');
    downloadText(md, `hexhawk-diff-${safeName}.md`, 'text/markdown');
  };

  const handleExportDiffJson = () => {
    if (!comparison || !selectedSnapshot) return;
    const payload = {
      generatedAt: new Date().toISOString(),
      binaryName: currentSnapshot.binaryName,
      current: currentSnapshot,
      baseline: selectedSnapshot,
      comparison,
    };
    const safeName = currentSnapshot.binaryName.replace(/[^a-zA-Z0-9_-]/g, '_');
    downloadText(JSON.stringify(payload, null, 2), `hexhawk-diff-${safeName}.json`, 'application/json');
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
          <button className="report-btn" onClick={handleSaveSnapshot}>
            {saved ? '✓ Saved' : '☆ Save Snapshot'}
          </button>
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

      <details className="report-section report-ai-contributions" open>
        <summary className="report-section-title">How AI contributed</summary>
        <p>
          {reportAiContributions.present
            ? 'This report includes labelled AI interpretation sections. They are advisory notes only and are separate from static evidence.'
            : 'No AI observations were generated for this analysis. The report is based on static analysis and GYRE output.'}
        </p>
        <p>GYRE remains the sole verdict authority. AI did not affect the GYRE verdict or NEST evidence convergence.</p>
        {reportAiContributions.sections.length > 0 && (
          <ul>
            {reportAiContributions.sections.map(section => (
              <li key={`${section.section}-${section.source}`}>
                {formatAiSectionLabel(section.section)} — {formatAiSourceLabel(section.source)} ({formatAiRole(section.section)})
                {typeof section.count === 'number' ? `, ${section.count} item(s)` : ''}
              </li>
            ))}
          </ul>
        )}
      </details>

      {/* ── Binary metadata ─────────────────────────────────────── */}
      {(binaryPath || architecture || fileType) && (
        <div className="report-meta-strip">
          {binaryPath && <span><span className="meta-label">File:</span> {binaryPath.split(/[\\/]/).pop()}</span>}
          {architecture && <span><span className="meta-label">Arch:</span> {architecture}</span>}
          {fileType && <span><span className="meta-label">Type:</span> {fileType}</span>}
          {binarySize && <span><span className="meta-label">Size:</span> {binarySize.toLocaleString()} bytes</span>}
        </div>
      )}

      <div className="report-section" data-testid="report-aetherframe-policy">
        <div className="report-section-title">AETHERFRAME Report Packaging Policy</div>
        <label className="report-policy-toggle">
          <input
            type="checkbox"
            checked={aetherframeMarkdownEnabled}
            onChange={(event) => setAetherframeMarkdownEnabled(event.target.checked)}
          />
          <span>Apply AETHERFRAME lineage to Markdown and copy exports</span>
        </label>
        <p className="report-policy-note">
          {aetherframeMarkdownEnabled
            ? 'Enabled: AETHERFRAME may append package-only lineage, protected fields, blocked mutations, and proof limits. It does not change GYRE verdict truth.'
            : 'High-assurance export mode: Markdown and copy exports leave the report body unchanged; use this when AETHERFRAME must be disabled.'}
        </p>
      </div>

      {relevantSnapshots.length > 0 && (
        <div className="report-section">
          <div className="report-section-title">
            Saved Snapshots
            <span className="section-count">{relevantSnapshots.length}</span>
          </div>
          <div className="report-snapshot-list">
            {relevantSnapshots.map(snapshot => (
              <div
                key={snapshot.id}
                className={`report-snapshot-item${snapshot.id === selectedSnapshot?.id ? ' active' : ''}`}
              >
                <button
                  className="report-snapshot-item-btn"
                  onClick={() => setSelectedSnapshotId(snapshot.id)}
                  type="button"
                >
                  <span className="report-snapshot-score">{snapshot.threatScore}</span>
                  <span className="report-snapshot-meta">
                    <strong>{snapshot.classification}</strong>
                    <span>{new Date(snapshot.generatedAt).toLocaleString()}</span>
                  </span>
                </button>
                <textarea
                  className="report-snapshot-notes"
                  placeholder="Analyst notes…"
                  value={snapshot.notes ?? ''}
                  rows={1}
                  onChange={(e) => handleUpdateNote(snapshot.id, e.target.value)}
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {selectedSnapshot && comparison && (
        <div className="report-section">
          <div className="report-section-title">Snapshot Comparison</div>
          <div className="report-compare-card">
            <div className="report-compare-header">
              <div>
                Comparing current report against snapshot from {new Date(selectedSnapshot.generatedAt).toLocaleString()}
              </div>
              <div className="report-compare-subtitle">{selectedSnapshot.binaryName}</div>
              <div className="report-compare-export-actions">
                <button className="report-btn report-btn--sm" type="button" onClick={handleExportDiffMarkdown}>↓ Diff MD</button>
                <button className="report-btn report-btn--sm" type="button" onClick={handleExportDiffJson}>↓ Diff JSON</button>
              </div>
            </div>
            <div className="report-compare-grid">
              <div className="report-compare-metric">
                <span className="report-compare-label">Threat score delta</span>
                <strong>{formatDelta(comparison.threatScoreDelta)}</strong>
              </div>
              <div className="report-compare-metric">
                <span className="report-compare-label">Confidence delta</span>
                <strong>{formatDelta(comparison.confidenceDelta)}</strong>
              </div>
              <div className="report-compare-metric">
                <span className="report-compare-label">Signal delta</span>
                <strong>{formatDelta(comparison.signalCountDelta)}</strong>
              </div>
              <div className="report-compare-metric">
                <span className="report-compare-label">IOC delta</span>
                <strong>{formatDelta(comparison.iocCountDelta)}</strong>
              </div>
            </div>
            <div className="report-compare-summary">
              <div>
                <span className="report-compare-label">Classification drift</span>
                <strong>{comparison.classificationChanged ? `${selectedSnapshot.classification} → ${currentSnapshot.classification}` : 'unchanged'}</strong>
              </div>
              <div>
                <span className="report-compare-label">Behaviors added</span>
                <strong>{comparison.behaviorsAdded.length > 0 ? comparison.behaviorsAdded.join(', ') : 'none'}</strong>
              </div>
              <div>
                <span className="report-compare-label">Behaviors removed</span>
                <strong>{comparison.behaviorsRemoved.length > 0 ? comparison.behaviorsRemoved.join(', ') : 'none'}</strong>
              </div>
            </div>
          </div>
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
