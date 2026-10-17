import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { invoke } from '@tauri-apps/api/core';

interface ValueMatch {
  address: string;
  currentValue: number;
  previousValue: number | null;
}

interface ValueProcess {
  pid: number;
  name: string;
}

interface ValueScanSnapshot {
  scanId: number;
  pid: number;
  processName: string;
  valueType: 'i32';
  candidateCount: number;
  scannedBytes: number;
  scannedRegions: number;
  complete: boolean;
  matches: ValueMatch[];
  warnings: string[];
  authority: 'runtime_observation_not_gyre_verdict';
}

interface ValueEditPreview {
  confirmationToken: string;
}

interface ValueEditResult {
  pid: number;
  processName: string;
  address: string;
  originalValue: number;
  currentValue: number;
  rollbackToken: string | null;
}

interface ValueFreezePreview {
  confirmationToken: string;
  intervalMilliseconds: number;
}

interface ValueFreezeState {
  freezeId: string;
  pid: number;
  processName: string;
  address: string;
  originalValue: number;
  frozenValue: number;
  intervalMilliseconds: number;
  active: boolean;
  verifiedWrites: number;
  lastObservedValue: number | null;
  stopReason: string | null;
  restoredOriginal: boolean;
}

const parseI32 = (raw: string): number => {
  const text = raw.trim();
  const hex = /^([+-]?)0x([0-9a-f]+)$/i.exec(text);
  const value = hex
    ? (hex[1] === '-' ? -1 : 1) * Number.parseInt(hex[2], 16)
    : Number(text);
  if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
    throw new Error('Enter a whole number from -2,147,483,648 to 2,147,483,647.');
  }
  return value;
};

const explainFailure = (caught: unknown): string => {
  const message = String(caught);
  if (message.includes('did not retain the requested value')) {
    return 'The process rewrote this address immediately. It is probably a temporary or display copy. Change the visible value again, enter it in Step 2, run Next Scan, and use the newly retained result.';
  }
  if (message.includes('Candidate changed from') || message.includes('Originating candidate changed')) {
    return 'This address changed since the last scan. Enter the value currently shown in the program and run Next Scan before trying again.';
  }
  if (message.includes('process identity changed') || message.includes('process exited')) {
    return 'The process restarted or closed, so its addresses are no longer valid. Choose the process again and start a new scan.';
  }
  return message;
};

const explainFreezeState = (state: ValueFreezeState): string | null => {
  if (!state.stopReason) return null;
  if (state.stopReason.includes('temporary or display copy')) return state.stopReason;
  if (state.stopReason.includes('rewrote this address')) {
    return `${state.stopReason} If it stops, change the visible value and run Next Scan to find the current source.`;
  }
  return state.stopReason;
};

const GuidedValueFinderPanel: React.FC = () => {
  const [selectedProcess, setSelectedProcess] = useState<ValueProcess | null>(null);
  const [value, setValue] = useState('');
  const [snapshot, setSnapshot] = useState<ValueScanSnapshot | null>(null);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [editResult, setEditResult] = useState<ValueEditResult | null>(null);
  const [freezeSpeed, setFreezeSpeed] = useState('50');
  const [freezeState, setFreezeState] = useState<ValueFreezeState | null>(null);
  const [processes, setProcesses] = useState<ValueProcess[]>([]);
  const [processFilter, setProcessFilter] = useState('');
  const [processPickerOpen, setProcessPickerOpen] = useState(false);
  const [processesLoading, setProcessesLoading] = useState(false);
  const freezePollInFlight = useRef(false);
  const freezePollGeneration = useRef(0);

  useEffect(() => {
    if (!processPickerOpen) return undefined;
    const previousOverflow = document.body.style.overflow;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setProcessPickerOpen(false);
    };
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', closeOnEscape);
    };
  }, [processPickerOpen]);

  const loadProcesses = async () => {
    try {
      setProcessesLoading(true);
      setError(null);
      setProcesses(await invoke<ValueProcess[]>('value_process_list'));
      setProcessPickerOpen(true);
    } catch (caught) {
      setError(`Could not list running processes: ${String(caught)}`);
    } finally {
      setProcessesLoading(false);
    }
  };

  const visibleProcesses = processes.filter(process => {
    const query = processFilter.trim().toLocaleLowerCase();
    return !query || process.name.toLocaleLowerCase().includes(query) || String(process.pid).includes(query);
  });

  const stopActiveFreeze = async () => {
    if (!freezeState?.active) return;
    try {
      setFreezeState(await invoke<ValueFreezeState>('value_freeze_stop', {
        request: { freezeId: freezeState.freezeId, restoreOriginal: false },
      }));
    } catch {
      // The worker may already have stopped.
    }
  };

  const resetScan = async () => {
    const scanId = snapshot?.scanId;
    const activeRequestId = requestId;
    await stopActiveFreeze();
    setSnapshot(null);
    setRequestId(null);
    setSelectedAddress(null);
    setEditResult(null);
    setFreezeState(null);
    setEditValue('');
    if (scanId !== undefined) {
      try { await invoke('value_scan_cancel', { scanId }); } catch { /* already closed */ }
    }
    if (activeRequestId) {
      try { await invoke('value_scan_cancel_request', { requestId: activeRequestId }); } catch { /* already closed */ }
    }
  };

  const chooseProcess = async (process: ValueProcess) => {
    await resetScan();
    setSelectedProcess(process);
    setProcessPickerOpen(false);
    setError(null);
  };

  const applySnapshot = (result: ValueScanSnapshot) => {
    setSnapshot(result);
    setEditResult(null);
    setFreezeState(null);
    if (result.candidateCount === 1 && result.matches.length === 1) {
      setSelectedAddress(result.matches[0].address);
    } else if (!result.matches.some(match => match.address === selectedAddress)) {
      setSelectedAddress(null);
    }
  };

  const firstScan = async () => {
    if (!selectedProcess) {
      setError('Choose a running process in Step 1.');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const nextRequestId = `value-scan-${Date.now()}-${crypto.randomUUID()}`;
      setRequestId(nextRequestId);
      applySnapshot(await invoke<ValueScanSnapshot>('value_scan_start', {
        pid: selectedProcess.pid,
        request: {
          value: parseI32(value),
          maxScanBytes: null,
          authorized: true,
          requestId: nextRequestId,
        },
      }));
    } catch (caught) {
      setError(explainFailure(caught));
    } finally {
      setLoading(false);
    }
  };

  const nextScan = async () => {
    if (!snapshot) return;
    try {
      setLoading(true);
      setError(null);
      applySnapshot(await invoke<ValueScanSnapshot>('value_scan_refine', {
        scanId: snapshot.scanId,
        value: parseI32(value),
      }));
    } catch (caught) {
      setError(explainFailure(caught));
    } finally {
      setLoading(false);
    }
  };

  const setOnce = async () => {
    if (!snapshot || !selectedAddress) return;
    try {
      setLoading(true);
      setError(null);
      const preview = await invoke<ValueEditPreview>('value_edit_preview', {
        request: {
          scanId: snapshot.scanId,
          address: selectedAddress,
          newValue: parseI32(editValue),
          authorized: true,
        },
      });
      setEditResult(await invoke<ValueEditResult>('value_edit_commit', {
        request: { confirmationToken: preview.confirmationToken },
      }));
    } catch (caught) {
      setError(explainFailure(caught));
    } finally {
      setLoading(false);
    }
  };

  const undoSet = async () => {
    if (!editResult?.rollbackToken) return;
    try {
      setLoading(true);
      setError(null);
      setEditResult(await invoke<ValueEditResult>('value_edit_rollback', {
        rollbackToken: editResult.rollbackToken,
      }));
    } catch (caught) {
      setError(explainFailure(caught));
    } finally {
      setLoading(false);
    }
  };

  const startFreeze = async () => {
    if (!snapshot || !selectedAddress) return;
    try {
      setLoading(true);
      setError(null);
      const preview = await invoke<ValueFreezePreview>('value_freeze_preview', {
        request: {
          scanId: snapshot.scanId,
          address: selectedAddress,
          frozenValue: parseI32(editValue),
          authorized: true,
          intervalMilliseconds: Number(freezeSpeed),
        },
      });
      setFreezeState(await invoke<ValueFreezeState>('value_freeze_commit', {
        request: { confirmationToken: preview.confirmationToken },
      }));
    } catch (caught) {
      setError(explainFailure(caught));
    } finally {
      setLoading(false);
    }
  };

  const stopFreeze = async () => {
    if (!freezeState) return;
    try {
      setLoading(true);
      setError(null);
      setFreezeState(await invoke<ValueFreezeState>('value_freeze_stop', {
        request: { freezeId: freezeState.freezeId, restoreOriginal: false },
      }));
    } catch (caught) {
      setError(explainFailure(caught));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => () => {
    if (snapshot?.scanId !== undefined) {
      void Promise.resolve(invoke('value_scan_cancel', { scanId: snapshot.scanId })).catch(() => undefined);
    }
  }, [snapshot?.scanId]);

  useEffect(() => () => {
    if (requestId) {
      void Promise.resolve(invoke('value_scan_cancel_request', { requestId })).catch(() => undefined);
    }
  }, [requestId]);

  useEffect(() => () => {
    if (freezeState?.active) {
      void Promise.resolve(invoke('value_freeze_stop', {
        request: { freezeId: freezeState.freezeId, restoreOriginal: false },
      })).catch(() => undefined);
    }
  }, [freezeState?.active, freezeState?.freezeId]);

  useEffect(() => {
    const onPageHide = () => {
      if (snapshot?.scanId !== undefined) void Promise.resolve(invoke('value_scan_cancel', { scanId: snapshot.scanId })).catch(() => undefined);
      if (requestId) void Promise.resolve(invoke('value_scan_cancel_request', { requestId })).catch(() => undefined);
      if (freezeState?.active) void Promise.resolve(invoke('value_freeze_stop', { request: { freezeId: freezeState.freezeId, restoreOriginal: false } })).catch(() => undefined);
    };
    window.addEventListener('pagehide', onPageHide);
    return () => window.removeEventListener('pagehide', onPageHide);
  }, [freezeState?.active, freezeState?.freezeId, requestId, snapshot?.scanId]);

  useEffect(() => {
    if (!freezeState?.active) return undefined;
    const generation = ++freezePollGeneration.current;
    const timer = window.setInterval(() => {
      if (freezePollInFlight.current) return;
      freezePollInFlight.current = true;
      void invoke<ValueFreezeState>('value_freeze_status', { freezeId: freezeState.freezeId })
        .then(state => {
          if (freezePollGeneration.current === generation) setFreezeState(state);
        })
        .catch(caught => {
          if (freezePollGeneration.current === generation) setError(explainFailure(caught));
        })
        .finally(() => {
          if (freezePollGeneration.current === generation) freezePollInFlight.current = false;
        });
    }, 400);
    return () => {
      freezePollGeneration.current += 1;
      freezePollInFlight.current = false;
      window.clearInterval(timer);
    };
  }, [freezeState?.active, freezeState?.freezeId]);

  const candidateLabel = snapshot ? `${snapshot.candidateCount} ${snapshot.candidateCount === 1 ? 'candidate' : 'candidates'}` : null;
  const freezeMessage = freezeState ? explainFreezeState(freezeState) : null;

  return (
    <section className="vf-root vf-simple" aria-label="Guided value finder" data-workspace-section="flow">
      <div className="vf-simple-header">
        <div>
          <div className="stk-pane-title">Value Finder</div>
          <p>Find a number shown in a running program, then set or hold the matching memory value.</p>
        </div>
        <span className="vf-type-badge">Whole number · 4 bytes</span>
      </div>
      <details className="vf-capabilities">
        <summary>What can this scanner find?</summary>
        <p>Current build: exact signed 4-byte whole numbers and exact changed-value refinement. It does not yet scan floats, unknown initial values, pointer chains, or encoded values, and no local scanner can recover server-only or arbitrarily changing encrypted state.</p>
      </details>

      <section className={`vf-step ${selectedProcess ? 'vf-step--complete' : 'vf-step--active'}`}>
        <div className="vf-step-heading"><strong>1. Choose a process</strong><span>{selectedProcess ? 'Ready' : 'Required'}</span></div>
        <p>Select a process you own or are allowed to modify. Choosing it is the one authorization action for this Value Finder session.</p>
        <div className="vf-process-toolbar">
          <button className="stk-btn stk-btn--primary" type="button" onClick={() => void loadProcesses()} disabled={processesLoading || loading}>
            {processesLoading ? 'Loading…' : 'Choose process'}
          </button>
          {selectedProcess && <strong className="vf-selected-process">{selectedProcess.name} · PID {selectedProcess.pid}</strong>}
        </div>
      </section>

      {processPickerOpen && createPortal(
        <div className="vf-process-picker-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) setProcessPickerOpen(false); }}>
          <div className="vf-process-picker" role="dialog" aria-modal="true" aria-labelledby="vf-process-picker-title">
            <div className="vf-process-picker-header">
              <strong id="vf-process-picker-title">Choose a running process</strong>
              <button className="stk-btn" type="button" onClick={() => setProcessPickerOpen(false)}>Close</button>
            </div>
            <p className="pkt-subtitle">Choose only a process you own or have permission to modify.</p>
            <input aria-label="filter running processes" className="stk-bp-field" value={processFilter} onChange={event => setProcessFilter(event.target.value)} placeholder="Filter by application name or PID" autoFocus />
            <div className="vf-process-list" role="listbox" aria-label="Running processes">
              {visibleProcesses.map(process => (
                <button className="vf-process-row" type="button" role="option" aria-label={`${process.name} PID ${process.pid}`} aria-selected={selectedProcess?.pid === process.pid} key={process.pid} onClick={() => void chooseProcess(process)}>
                  <span>{process.name}</span><span>PID {process.pid}</span>
                </button>
              ))}
              {visibleProcesses.length === 0 && <div className="vf-process-empty">No running process matches this filter.</div>}
            </div>
          </div>
        </div>,
        document.body,
      )}

      <section className={`vf-step ${selectedProcess && !snapshot ? 'vf-step--active' : ''}`}>
        <div className="vf-step-heading"><strong>2. Find the value</strong><span>{candidateLabel ?? (snapshot ? 'Scanning' : 'Waiting')}</span></div>
        <p>{snapshot ? 'Change the value naturally in the program, enter the new value, then choose Next Scan.' : 'Enter the number currently visible in the program, then choose First Scan.'}</p>
        <div className="vf-controls vf-find-controls">
          <label className="vf-field-label"><span>Current visible value</span><input aria-label="current visible value" className="stk-bp-field" value={value} onChange={event => setValue(event.target.value)} placeholder="Example: 55" disabled={!selectedProcess || loading} /></label>
          {!snapshot ? (
            <button className="stk-btn stk-btn--primary" type="button" onClick={() => void firstScan()} disabled={!selectedProcess || loading}>First scan</button>
          ) : (
            <button className="stk-btn stk-btn--primary" type="button" onClick={() => void nextScan()} disabled={loading}>Next scan</button>
          )}
          <button className="stk-btn stk-btn--nav" type="button" onClick={() => void resetScan()} disabled={!snapshot || loading}>New scan</button>
        </div>
        {snapshot && (
          <>
            <div className="pkt-metrics vf-scan-summary">
              <span>{candidateLabel}</span><span>{snapshot.processName} · PID {snapshot.pid}</span><span>{snapshot.scannedRegions} regions</span><span>{Math.round(snapshot.scannedBytes / 1048576)} MiB read</span><span>{snapshot.complete ? 'full budget completed' : 'partial scan'}</span>
            </div>
            {!snapshot.complete && <div className="vf-guidance vf-guidance--warn">The scan reached its memory budget. Results are usable, but another matching address may exist outside the scanned range.</div>}
            {snapshot.warnings.map((warning, index) => <div className="vf-guidance vf-guidance--warn" key={index}>{warning}</div>)}
            <div className="vf-candidates">
              {snapshot.matches.map(candidate => (
                <button className={`pkt-row vf-candidate ${selectedAddress === candidate.address ? 'vf-candidate--selected' : ''}`} key={candidate.address} type="button" onClick={() => { setSelectedAddress(candidate.address); setEditResult(null); setFreezeState(null); }}>
                  <span className="pkt-method">{candidate.address}</span><span>{snapshot.valueType}</span><span>{candidate.previousValue === null ? candidate.currentValue : `${candidate.previousValue} → ${candidate.currentValue}`}</span><span className="pkt-time">{selectedAddress === candidate.address ? 'selected' : 'use'}</span>
                </button>
              ))}
            </div>
          </>
        )}
      </section>

      <section className={`vf-step ${selectedAddress ? 'vf-step--active' : ''}`}>
        <div className="vf-step-heading"><strong>3. Set or freeze</strong><span>{selectedAddress ? 'Ready' : 'Select one result'}</span></div>
        {selectedAddress ? <p className="vf-selected-address">Selected address: {selectedAddress}</p> : <p>Refine the scan and select a result. A single remaining result is selected automatically.</p>}
        <div className="vf-control-value-row">
          <label className="vf-field-label"><span>New value</span><input aria-label="new value" className="stk-bp-field" value={editValue} onChange={event => setEditValue(event.target.value)} placeholder="Value to set or freeze" disabled={!selectedAddress || loading || freezeState?.active} /></label>
          <button className="stk-btn stk-btn--primary" type="button" onClick={() => void setOnce()} disabled={!selectedAddress || loading || freezeState?.active}>Set value</button>
          <label className="vf-speed-label"><span>Freeze speed</span><select aria-label="freeze speed" value={freezeSpeed} onChange={event => setFreezeSpeed(event.target.value)} disabled={!selectedAddress || loading || freezeState?.active}><option value="50">Responsive · 50 ms</option><option value="100">Balanced · 100 ms</option><option value="250">Gentle · 250 ms</option></select></label>
          {!freezeState?.active ? (
            <button className="stk-btn vf-freeze-button" type="button" onClick={() => void startFreeze()} disabled={!selectedAddress || loading}>Freeze value</button>
          ) : (
            <button className="stk-btn stk-btn--danger" type="button" onClick={() => void stopFreeze()} disabled={loading}>Stop Freeze</button>
          )}
        </div>
        {editResult && <div className="vf-guidance vf-guidance--ok"><strong>Set successfully: {editResult.originalValue} → {editResult.currentValue}</strong>{editResult.rollbackToken && <button className="stk-btn stk-btn--nav" type="button" onClick={() => void undoSet()} disabled={loading}>Undo</button>}</div>}
        {freezeState && <div className={`vf-guidance ${freezeState.active ? 'vf-guidance--active' : 'vf-guidance--warn'}`}><strong>{freezeState.active ? `Freeze active · ${freezeState.frozenValue}` : `Freeze stopped · ${freezeState.frozenValue}`}</strong><span>{freezeState.verifiedWrites} verified writes · every {freezeState.intervalMilliseconds} ms</span>{freezeMessage && <span>{freezeMessage}</span>}</div>}
      </section>

      {loading && <div className="vf-guidance">Working…</div>}
      {error && <div className="vf-guidance vf-guidance--error" role="alert"><strong>Could not complete that action.</strong><span>{error}</span></div>}
      <div className="pkt-boundary">Value Finder uses retained scan results only; it does not accept arbitrary addresses, inject code, hide from protection software, or bypass anti-cheat. Process restarts and new games can relocate values, so start a new scan when a previously working address becomes stale.</div>
    </section>
  );
};

export default GuidedValueFinderPanel;
