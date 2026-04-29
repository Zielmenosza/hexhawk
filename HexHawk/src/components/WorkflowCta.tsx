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
        <h2 className="wf-cta-title">No binary loaded</h2>
        <p className="wf-cta-body">Drop a file anywhere or click below to get started.</p>
        <button type="button" className="wf-cta-primary-btn" onClick={onLoadFile}>
          📂 Load Binary
        </button>
      </div>
    );
  }

  if (workflowState === 'fileLoaded') {
    return (
      <div className="wf-cta wf-cta--center">
        <div className="wf-cta-icon">📄</div>
        <h2 className="wf-cta-title">{fileName}</h2>
        <p className="wf-cta-body">File loaded. Run a quick metadata inspection to start.</p>
        <button type="button" className="wf-cta-primary-btn" onClick={onInspect}>
          🔎 Inspect File
        </button>
      </div>
    );
  }

  if (workflowState === 'inspected') {
    return (
      <div className="wf-cta">
        <h2 className="wf-cta-title">Inspection complete</h2>
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
        <p className="wf-cta-body">Choose your next step:</p>
        <div className="wf-cta-actions">
          {!hasDisassembly && (
            <button type="button" className="wf-cta-action-btn" onClick={onDisassemble}>⊞ Disassemble</button>
          )}
          {!hasCfg && (
            <button type="button" className="wf-cta-action-btn" onClick={onBuildCfg}>⬡ Build CFG</button>
          )}
          {!hasStrings && (
            <button type="button" className="wf-cta-action-btn" onClick={onScanStrings}>𝕊 Scan Strings</button>
          )}
          <button type="button" className="wf-cta-primary-btn" onClick={onRunAnalysis}>⚡ Run Full Analysis</button>
        </div>
      </div>
    );
  }

  // analyzed — show the verdict CTA
  return (
    <div className="wf-cta wf-cta--center">
      <div className="wf-cta-icon">⚖</div>
      <h2 className="wf-cta-title">Analysis complete</h2>
      <p className="wf-cta-body">Intelligence is ready. View the verdict to understand the binary.</p>
      <button type="button" className="wf-cta-primary-btn" onClick={onViewVerdict}>
        ⚖ View Verdict
      </button>
    </div>
  );
}
