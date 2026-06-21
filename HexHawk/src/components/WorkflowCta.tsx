import React from 'react';
import type { WorkflowState } from './WorkflowNav';

interface WorkflowCtaProps {
  workflowState: WorkflowState;
  fileName: string;
  hasDisassembly: boolean;
  hasCfg: boolean;
  hasStrings: boolean;
  onLoadFile: () => void;
  onInspect: () => void;
  onDisassemble: () => void;
  onBuildCfg: () => void;
  onScanStrings: () => void;
  onRunAnalysis: () => void;
  onViewVerdict: () => void;
}

export default function WorkflowCta({
  workflowState,
  fileName,
  hasDisassembly,
  hasCfg,
  hasStrings,
  onLoadFile,
  onInspect,
  onDisassemble,
  onBuildCfg,
  onScanStrings,
  onRunAnalysis,
  onViewVerdict,
}: WorkflowCtaProps) {
  if (workflowState === 'noFile') {
    return (
      <div className="wf-cta wf-cta--center">
        <div className="wf-cta-icon">📭</div>
        <h2 className="wf-cta-title">No file loaded</h2>
        <p className="wf-cta-body">Drop in a file you are allowed to inspect, or click below to choose one. HexHawk starts by reading local file facts such as type and hashes.</p>
        <button type="button" className="wf-cta-primary-btn" onClick={onLoadFile}>
          📂 Open File
        </button>
      </div>
    );
  }

  if (workflowState === 'fileLoaded') {
    return (
      <div className="wf-cta wf-cta--center">
        <div className="wf-cta-icon">📄</div>
        <h2 className="wf-cta-title">{fileName}</h2>
        <p className="wf-cta-body">File selected. Start with Inspect File so HexHawk can record identity, hashes, sections, imports, and exports before deeper analysis.</p>
        <button type="button" className="wf-cta-primary-btn" onClick={onInspect}>
          🔎 Inspect File
        </button>
      </div>
    );
  }

  if (workflowState === 'inspected') {
    return (
      <div className="wf-cta">
        <h2 className="wf-cta-title">Inspection complete — choose the next evidence step</h2>
        <div className="wf-cta-checks">
          <span className="wf-cta-check wf-cta-check--done">✔ Metadata extracted</span>
          <span className={`wf-cta-check ${hasStrings ? 'wf-cta-check--done' : ''}`}>
            {hasStrings ? '✔' : '○'} Strings scanned
          </span>
          <span className={`wf-cta-check ${hasDisassembly ? 'wf-cta-check--done' : ''}`}>
            {hasDisassembly ? '✔' : '○'} Disassembled
          </span>
          <span className={`wf-cta-check ${hasCfg ? 'wf-cta-check--done' : ''}`}>
            {hasCfg ? '✔' : '○'} CFG built
          </span>
        </div>
        <p className="wf-cta-body">Recommended path: scan strings for readable clues, disassemble for code instructions, build the branch map, then run analysis for the verdict summary.</p>
        <div className="wf-cta-actions">
          {!hasDisassembly && (
            <button type="button" className="wf-cta-action-btn" onClick={onDisassemble}>⊞ Disassemble code</button>
          )}
          {!hasCfg && (
            <button type="button" className="wf-cta-action-btn" onClick={onBuildCfg}>⬡ Build branch map</button>
          )}
          {!hasStrings && (
            <button type="button" className="wf-cta-action-btn" onClick={onScanStrings}>𝕊 Find readable strings</button>
          )}
          <button type="button" className="wf-cta-primary-btn" onClick={onRunAnalysis}>⚡ Run analysis and show verdict</button>
        </div>
      </div>
    );
  }

  // analyzed — show the verdict CTA
  return (
    <div className="wf-cta wf-cta--center">
      <div className="wf-cta-icon">⚖</div>
      <h2 className="wf-cta-title">Analysis complete</h2>
      <p className="wf-cta-body">The first analysis pass is ready. Open the verdict to see the GYRE classification, confidence, supporting evidence, contradictions, and next review steps.</p>
      <button type="button" className="wf-cta-primary-btn" onClick={onViewVerdict}>
        ⚖ View Verdict
      </button>
    </div>
  );
}
