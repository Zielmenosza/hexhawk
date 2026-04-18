import React, { useState, useEffect, useRef } from 'react';

interface Props {
  open: boolean;
  onClose: () => void;
  onJump: (address: number) => void;
  recentAddresses?: number[];
  formatHex?: (n: number) => string;
}

export default function JumpToAddressDialog({ open, onClose, onJump, recentAddresses = [], formatHex }: Props) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const fmt = formatHex ?? ((n: number) => '0x' + n.toString(16).toUpperCase().padStart(8, '0'));

  useEffect(() => {
    if (open) {
      setValue('');
      setError('');
      // Focus after the DOM updates
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  function parseAddress(raw: string): number | null {
    const s = raw.trim().replace(/^0x/i, '');
    if (!/^[0-9a-f]+$/i.test(s) || s.length === 0) return null;
    const n = parseInt(s, 16);
    return isFinite(n) ? n : null;
  }

  function handleJump() {
    const addr = parseAddress(value);
    if (addr === null) {
      setError('Enter a valid hex address (e.g. 0x401000 or 401000)');
      return;
    }
    onJump(addr);
    onClose();
  }

  if (!open) return null;

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog-box" onClick={(e) => e.stopPropagation()}>
        <div className="dialog-header">
          <span className="dialog-title">Jump to Address</span>
          <button type="button" className="dialog-close" onClick={onClose}>✕</button>
        </div>

        <div className="dialog-body">
          <input
            ref={inputRef}
            type="text"
            className={`dialog-input${error ? ' dialog-input-error' : ''}`}
            placeholder="0x401000"
            value={value}
            onChange={(e) => { setValue(e.target.value); setError(''); }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleJump();
            }}
            spellCheck={false}
            autoComplete="off"
          />
          {error && <div className="dialog-error">{error}</div>}
        </div>

        {recentAddresses.length > 0 && (
          <div className="dialog-recents">
            <div className="dialog-recents-title">Recent</div>
            <div className="dialog-recents-list">
              {recentAddresses.slice(0, 8).map((addr) => (
                <button
                  key={addr}
                  type="button"
                  className="dialog-recent-item"
                  onClick={() => { onJump(addr); onClose(); }}
                >
                  {fmt(addr)}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="dialog-footer">
          <button type="button" className="dialog-btn dialog-btn-cancel" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="dialog-btn dialog-btn-confirm" onClick={handleJump}>
            Jump
          </button>
        </div>
      </div>
    </div>
  );
}
