/**
 * PatchPanel — Milestone 2: Binary Patch Engine
 *
 * Displays the list of pending patches for the currently loaded binary.
 * Patches are accumulated in App state and applied to a copy when the user
 * clicks "Export Patched Binary".  The original file is never modified.
 *
 * Patch sources:
 *   • Disassembly view — "Invert Jump" and "NOP out" quick-action buttons
 *   • Patch Intelligence — explainable suggestions from detectPatchableBranches()
 *   • Hex viewer — manual byte edits (future: M1 streaming hex)
 */
import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { PatchSuggestion, PatchRiskLevel } from '../utils/patchEngine';
import { sanitizeAddress, sanitizeBridgePath } from '../utils/tauriGuards';

export type Patch = {
  id: string;
  address: number;
  /** Human-readable label, e.g. "JZ → JNZ" or "NOP ×6" */
  label: string;
  originalBytes: number[];
  patchedBytes: number[];
  enabled: boolean;
  timestamp: number;
  // ── Explainability fields (optional — absent on manual patches) ───────────
  /** One-sentence reason why this patch was suggested */
  reason?: string;
  /** What applying the patch will do to execution flow */
  impact?: string;
  /** What the analyst should verify before applying */
  verifyBefore?: string;
  /** Risk level of applying this patch */
  risk?: PatchRiskLevel;
  /** GYRE signal IDs that triggered this suggestion */
  signalIds?: string[];
};

interface PatchPanelProps {
  patches: Patch[];
  binaryPath: string;
  onRemovePatch: (id: string) => void;
  onTogglePatch: (id: string) => void;
  onClearAll: () => void;
  /** Explainable patch suggestions from the Patch Intelligence engine */
  suggestions?: PatchSuggestion[];
  /** Queue a suggestion as a pending patch (user-initiated) */
  onQueueSuggestion?: (s: PatchSuggestion) => void;
}

function formatHex(n: number) {
  return `0x${n.toString(16).toUpperCase().padStart(8, '0')}`;
}

function bytesToHex(bytes: number[]) {
  return bytes.map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}

const RISK_COLOR: Record<string, string> = {
  low:    'var(--patch-risk-low,    #4ec9b0)',
  medium: 'var(--patch-risk-medium, #dca84c)',
  high:   'var(--patch-risk-high,   #f14c4c)',
};

/** Collapsed / expanded explainability card for a queued patch */
function PatchExplainBox({ patch }: { patch: Patch }) {
  const [open, setOpen] = useState(false);
  if (!patch.reason && !patch.impact && !patch.verifyBefore) return null;
  return (
    <div className="patch-explain-box">
      <button
        className="patch-explain-toggle"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
      >
        {open ? '▾ Hide explanation' : '▸ Why this patch?'}
      </button>
      {open && (
        <div className="patch-explain-body">
          {patch.risk && (
            <div className="patch-explain-row">
              <span className="patch-explain-label">Risk</span>
              <span
                className="patch-risk-badge"
                style={{ color: RISK_COLOR[patch.risk] }}
              >
                {patch.risk.toUpperCase()}
              </span>
            </div>
          )}
          {patch.reason && (
            <div className="patch-explain-row">
              <span className="patch-explain-label">Reason</span>
              <span className="patch-explain-value">{patch.reason}</span>
            </div>
          )}
          {patch.impact && (
            <div className="patch-explain-row">
              <span className="patch-explain-label">Impact</span>
              <span className="patch-explain-value">{patch.impact}</span>
            </div>
          )}
          {patch.verifyBefore && (
            <div className="patch-explain-row patch-explain-row--warn">
              <span className="patch-explain-label">Verify first</span>
              <span className="patch-explain-value">{patch.verifyBefore}</span>
            </div>
          )}
          {patch.signalIds && patch.signalIds.length > 0 && (
            <div className="patch-explain-row">
              <span className="patch-explain-label">Signals</span>
              <span className="patch-explain-value">
                {patch.signalIds.map(id => (
                  <code key={id} className="patch-signal-chip">{id}</code>
                ))}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const PatchPanel: React.FC<PatchPanelProps> = ({
  patches,
  binaryPath,
  onRemovePatch,
  onTogglePatch,
  onClearAll,
  suggestions = [],
  onQueueSuggestion,
}) => {
  const [exporting, setExporting] = useState(false);
  const [exportResult, setExportResult] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [expandedSuggestion, setExpandedSuggestion] = useState<string | null>(null);

  const enabledPatches = patches.filter((p) => p.enabled);

  async function handleExport() {
    if (enabledPatches.length === 0) return;
    setExporting(true);
    setExportResult(null);
    setExportError(null);
    try {
      const safeBinaryPath = sanitizeBridgePath(binaryPath, 'binary path');
      const specs = enabledPatches.map((p) => ({
        offset: sanitizeAddress(p.address, 'patch offset'),
        new_bytes: p.patchedBytes,
      }));
      const result = await invoke<{
        patched_path: string;
        patches_applied: number;
        bytes_modified: number;
      }>('export_patched', { path: safeBinaryPath, patches: specs });
      setExportResult(
        `Saved: ${result.patched_path}  (${result.patches_applied} patch${result.patches_applied !== 1 ? 'es' : ''}, ${result.bytes_modified} bytes modified)`
      );
    } catch (err) {
      setExportError(String(err));
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="patch-panel">
      <div className="patch-panel-header">
        <div className="patch-panel-title">
          <span className="patch-panel-icon">🩹</span>
          <span>Patch Engine</span>
          {patches.length > 0 && (
            <span className="patch-count-badge">{patches.length}</span>
          )}
        </div>
        <div className="patch-panel-actions">
          <button
            className="patch-btn primary"
            disabled={enabledPatches.length === 0 || exporting}
            onClick={handleExport}
            title={`Apply ${enabledPatches.length} enabled patch${enabledPatches.length !== 1 ? 'es' : ''} to a copy`}
          >
            {exporting ? 'Exporting…' : `Export Patched Binary (${enabledPatches.length})`}
          </button>
          {patches.length > 0 && (
            <button
              className="patch-btn danger"
              onClick={onClearAll}
              title="Remove all pending patches"
            >
              Clear All
            </button>
          )}
        </div>
      </div>

      {exportResult && (
        <div className="patch-banner success">
          <span>✓</span> {exportResult}
        </div>
      )}
      {exportError && (
        <div className="patch-banner error">
          <span>⚠</span> {exportError}
        </div>
      )}

      {patches.length === 0 ? (
        <div className="patch-empty">
          <p>No patches queued.</p>
          <p className="patch-hint">
            Right-click a conditional jump in the Disassembly view and choose
            <strong> Invert Jump</strong>, or click <strong>NOP out</strong> on any
            instruction to add a patch here.
          </p>
        </div>
      ) : (
        <div className="patch-list">
          {patches.map((patch) => (
            <div
              key={patch.id}
              className={`patch-card${patch.enabled ? '' : ' disabled'}`}
            >
              <div className="patch-card-left">
                <label className="patch-toggle" title="Enable / disable this patch">
                  <input
                    type="checkbox"
                    checked={patch.enabled}
                    onChange={() => onTogglePatch(patch.id)}
                  />
                  <span className="patch-toggle-slider" />
                </label>
              </div>
              <div className="patch-card-body">
                <div className="patch-card-header-row">
                  <code className="patch-address">{formatHex(patch.address)}</code>
                  <span className="patch-label">{patch.label}</span>
                  {patch.risk && (
                    <span
                      className="patch-risk-badge"
                      style={{ color: RISK_COLOR[patch.risk] }}
                      title={`Risk level: ${patch.risk}`}
                    >
                      {patch.risk.toUpperCase()}
                    </span>
                  )}
                </div>
                <div className="patch-bytes-row">
                  <span className="patch-bytes-before">
                    <span className="patch-bytes-tag">Before:</span>
                    <code>{bytesToHex(patch.originalBytes)}</code>
                  </span>
                  <span className="patch-bytes-arrow">→</span>
                  <span className="patch-bytes-after">
                    <span className="patch-bytes-tag">After:</span>
                    <code>{bytesToHex(patch.patchedBytes)}</code>
                  </span>
                </div>
                <PatchExplainBox patch={patch} />
              </div>
              <button
                className="patch-remove-btn"
                onClick={() => onRemovePatch(patch.id)}
                title="Remove this patch"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      {/* ── Patch Intelligence — explainable suggestions ─────────────────── */}
      {suggestions.length > 0 && (
        <div className="patch-suggestions">
          <div className="patch-suggestions-header">
            <span className="patch-suggestions-title">Patch Intelligence</span>
            <span className="patch-suggestions-count">{suggestions.length} suggestion{suggestions.length !== 1 ? 's' : ''}</span>
            <span className="patch-suggestions-note">Not applied — review before queuing</span>
          </div>
          <div className="patch-suggestions-list">
            {suggestions.map((s) => {
              const isExpanded = expandedSuggestion === s.id;
              const alreadyQueued = patches.some(p => p.address === s.address);
              return (
                <div
                  key={s.id}
                  className={`patch-suggestion-card${alreadyQueued ? ' patch-suggestion-card--queued' : ''}`}
                >
                  <div className="patch-suggestion-top">
                    <code className="patch-address">{formatHex(s.address)}</code>
                    <span className="patch-label">{s.label}</span>
                    <span
                      className="patch-risk-badge"
                      style={{ color: RISK_COLOR[s.risk] }}
                      title={`Risk: ${s.risk}`}
                    >
                      {s.risk.toUpperCase()}
                    </span>
                    {alreadyQueued && (
                      <span className="patch-queued-badge">Queued</span>
                    )}
                  </div>

                  <div className="patch-suggestion-reason">{s.reason}</div>

                  {s.signalLinks.length > 0 && (
                    <div className="patch-suggestion-signals">
                      {s.signalLinks.map(link => (
                        <span
                          key={link.signalId}
                          className="patch-signal-chip"
                          title={link.finding}
                        >
                          {link.signalId}
                        </span>
                      ))}
                    </div>
                  )}

                  <button
                    className="patch-suggestion-expand"
                    onClick={() => setExpandedSuggestion(isExpanded ? null : s.id)}
                    aria-expanded={isExpanded}
                  >
                    {isExpanded ? '▾ Hide details' : '▸ Show impact & checklist'}
                  </button>

                  {isExpanded && (
                    <div className="patch-suggestion-details">
                      <div className="patch-explain-row">
                        <span className="patch-explain-label">Impact</span>
                        <span className="patch-explain-value">{s.impact}</span>
                      </div>
                      <div className="patch-explain-row patch-explain-row--warn">
                        <span className="patch-explain-label">Verify first</span>
                        <span className="patch-explain-value">{s.verifyBefore}</span>
                      </div>
                      {s.logicRegion && (
                        <div className="patch-explain-row">
                          <span className="patch-explain-label">Region</span>
                          <span className="patch-explain-value">
                            {s.logicRegion.kind} · {s.logicRegion.summary} · confidence {Math.round(s.logicRegion.confidence * 100)}%
                          </span>
                        </div>
                      )}
                    </div>
                  )}

                  {!alreadyQueued && onQueueSuggestion && (
                    <button
                      className="patch-suggestion-queue-btn"
                      onClick={() => onQueueSuggestion(s)}
                      title="Queue this patch for review — does not apply it immediately"
                    >
                      + Queue for review
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default PatchPanel;
