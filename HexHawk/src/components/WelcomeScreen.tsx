/**
 * WelcomeScreen — First-run onboarding experience for HexHawk.
 *
 * Shown on the first launch (localStorage key 'hexhawk.firstRunComplete' absent).
 * Guides the analyst through the key capabilities in < 60 seconds.
 * Provides a "Load sample binary" quick-start path.
 */
import React, { useState, useCallback } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface WelcomeScreenProps {
  /** Called when the user dismisses the screen. Pass `permanent=true` to never show again. */
  onDismiss: (permanent: boolean) => void;
  /** Optional: opens the file dialog for the user to load their first binary */
  onOpenFile?: () => void;
}

interface Step {
  id: string;
  icon: string;
  title: string;
  body: string;
  tip: string;
}

// ─── Content ──────────────────────────────────────────────────────────────────

const STEPS: Step[] = [
  {
    id: 'load',
    icon: '📂',
    title: 'Load a binary',
    body: 'Open any Windows PE (.exe, .dll), raw binary, or ELF file. HexHawk inspects it without executing — completely safe, fully offline.',
    tip: 'Tip: try dropping a file directly onto the window.',
  },
  {
    id: 'verdict',
    icon: '⚖️',
    title: 'Read the verdict',
    body: 'The top-left panel shows a threat score 0–100, classification, and an explainable reasoning chain — every signal that contributed to the verdict, weighted and auditable.',
    tip: 'Tip: click any signal to jump to the relevant hex/disassembly location.',
  },
  {
    id: 'talon',
    icon: '🦅',
    title: 'TALON — decompile functions',
    body: 'The TALON tab generates pseudo-C for any function with per-line confidence scores, intent annotations, and loop structure analysis powered by SSA-form IR.',
    tip: 'Tip: functions with ⚠ annotations have detected security-relevant behaviour.',
  },
  {
    id: 'nest',
    icon: '🔁',
    title: 'NEST — iterative convergence',
    body: 'NEST re-analyses the binary across multiple passes, expanding disassembly coverage and refining the verdict until it stabilises. No other tool does this.',
    tip: 'Tip: enable Auto-Advance for fully automatic deep analysis.',
  },
  {
    id: 'console',
    icon: '💬',
    title: 'Operator Console',
    body: 'Type what you want to know in plain text — "check for anti-debug techniques", "map the network traffic", "find persistence mechanisms" — and get a step-by-step workflow.',
    tip: 'Tip: the Console tab is the fastest way to start a structured analysis.',
  },
  {
    id: 'strike',
    icon: '⚡',
    title: 'STRIKE — runtime behaviour',
    body: 'STRIKE attaches a debugger, steps through execution, and surfaces behavioural anomalies: timing checks, ROP gadgets, stack pivots, and register delta timelines.',
    tip: 'Tip: use STRIKE for dynamic validation after TALON flags suspicious functions.',
  },
];

// ─── Sub-components ───────────────────────────────────────────────────────────

function ProgressDots({ total, current }: { total: number; current: number }) {
  return (
    <div style={{ display: 'flex', gap: 6, justifyContent: 'center', marginTop: 16 }}>
      {Array.from({ length: total }, (_, i) => (
        <div
          key={i}
          style={{
            width: i === current ? 20 : 8,
            height: 8,
            borderRadius: 4,
            background: i === current ? '#00d4ff' : i < current ? '#00d4ff66' : '#ffffff22',
            transition: 'width 0.2s ease, background 0.2s ease',
          }}
        />
      ))}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function WelcomeScreen({ onDismiss, onOpenFile }: WelcomeScreenProps) {
  const [step, setStep] = useState(0);
  const isLast = step === STEPS.length - 1;
  const current = STEPS[step];

  const next = useCallback(() => {
    if (isLast) {
      onDismiss(true);
    } else {
      setStep(s => s + 1);
    }
  }, [isLast, onDismiss]);

  const prev = useCallback(() => setStep(s => Math.max(0, s - 1)), []);

  const skip = useCallback(() => onDismiss(false), [onDismiss]);

  return (
    <div
      className="welcome-overlay"
      style={{
        position: 'fixed', inset: 0, zIndex: 9999,
        background: 'rgba(10,12,18,0.92)',
        backdropFilter: 'blur(8px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
    >
      <div
        className="welcome-card"
        style={{
          background: 'linear-gradient(135deg, #161b26 0%, #1c2235 100%)',
          border: '1px solid #2a3050',
          borderRadius: 16,
          padding: '40px 48px',
          maxWidth: 560,
          width: '90vw',
          color: '#e0e6f0',
          boxShadow: '0 32px 80px rgba(0,0,0,0.6)',
          position: 'relative',
        }}
      >
        {/* Skip */}
        <button
          onClick={skip}
          style={{
            position: 'absolute', top: 16, right: 20,
            background: 'none', border: 'none', color: '#5a6a8a',
            cursor: 'pointer', fontSize: 13,
          }}
        >
          Skip intro
        </button>

        {/* Step icon + step counter */}
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <div style={{ fontSize: 48, lineHeight: 1, marginBottom: 8 }}>{current.icon}</div>
          <div style={{ fontSize: 11, color: '#5a6a8a', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
            {step + 1} / {STEPS.length}
          </div>
        </div>

        {/* HexHawk branding (step 0 only) */}
        {step === 0 && (
          <div style={{ textAlign: 'center', marginBottom: 24 }}>
            <div style={{
              fontSize: 28, fontWeight: 700, color: '#00d4ff',
              letterSpacing: '-0.02em',
            }}>
              HexHawk
            </div>
            <div style={{ fontSize: 13, color: '#7a8aaa', marginTop: 4 }}>
              Binary Analysis & Reverse Engineering Workbench
            </div>
          </div>
        )}

        {/* Title */}
        <h2 style={{ margin: '0 0 12px', fontSize: 22, fontWeight: 600, color: '#e8eef8' }}>
          {current.title}
        </h2>

        {/* Body */}
        <p style={{ margin: '0 0 16px', fontSize: 15, lineHeight: 1.65, color: '#b0bcd0' }}>
          {current.body}
        </p>

        {/* Tip */}
        <div style={{
          background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.18)',
          borderRadius: 8, padding: '10px 14px',
          fontSize: 13, color: '#80c8e0', lineHeight: 1.5,
          marginBottom: 28,
        }}>
          {current.tip}
        </div>

        {/* Quick-start CTA on last step */}
        {isLast && onOpenFile && (
          <button
            onClick={() => { onOpenFile(); onDismiss(true); }}
            style={{
              display: 'block', width: '100%', marginBottom: 12,
              padding: '12px 0',
              background: 'linear-gradient(90deg, #0088cc, #00d4ff)',
              border: 'none', borderRadius: 8,
              color: '#fff', fontWeight: 700, fontSize: 15,
              cursor: 'pointer', letterSpacing: '0.02em',
            }}
          >
            Open a binary now →
          </button>
        )}

        {/* Navigation */}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'space-between', alignItems: 'center' }}>
          <button
            onClick={prev}
            disabled={step === 0}
            style={{
              padding: '9px 20px', background: 'none',
              border: '1px solid #2a3050', borderRadius: 7,
              color: step === 0 ? '#3a4060' : '#8090b0', cursor: step === 0 ? 'default' : 'pointer',
              fontSize: 14,
            }}
          >
            ← Back
          </button>

          <ProgressDots total={STEPS.length} current={step} />

          <button
            onClick={next}
            style={{
              padding: '9px 24px',
              background: isLast ? '#00d4ff22' : '#1e2d4a',
              border: `1px solid ${isLast ? '#00d4ff88' : '#3a4a6a'}`,
              borderRadius: 7, color: isLast ? '#00d4ff' : '#c0d0e8',
              cursor: 'pointer', fontSize: 14, fontWeight: isLast ? 600 : 400,
            }}
          >
            {isLast ? 'Get started' : 'Next →'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Helper: should we show the welcome screen? ───────────────────────────────

const STORAGE_KEY = 'hexhawk.firstRunComplete';

export function shouldShowWelcome(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) !== 'true';
  } catch {
    return false;
  }
}

export function markFirstRunComplete(): void {
  try {
    localStorage.setItem(STORAGE_KEY, 'true');
  } catch {
    // localStorage unavailable (private browsing, etc.)
  }
}
