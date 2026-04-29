import { describe, it, expect } from 'vitest';
import {
  createTimeline,
  appendStep,
  MAX_STRIKE_TIMELINE_STEPS,
} from '../strikeEngine';
import type { DebugSnapshot, RegisterState } from '../../components/DebuggerPanel';

function makeRegisters(rip: number): RegisterState {
  return {
    rax: 0,
    rbx: 0,
    rcx: 0,
    rdx: 0,
    rsi: 0,
    rdi: 0,
    rsp: 0x1000,
    rbp: 0x2000,
    rip,
    r8: 0,
    r9: 0,
    r10: 0,
    r11: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    eflags: 0,
    cs: 0,
    ss: 0,
  };
}

function makeSnapshot(stepCount: number, rip: number): DebugSnapshot {
  return {
    sessionId: 7,
    status: 'Paused',
    registers: makeRegisters(rip),
    stack: [],
    breakpoints: [],
    stepCount,
    exitCode: null,
    lastEvent: 'step',
  };
}

describe('strikeEngine appendStep', () => {
  it('caps timeline steps and reindexes when over limit', () => {
    let timeline = createTimeline(7);

    const total = MAX_STRIKE_TIMELINE_STEPS + 20;
    for (let i = 0; i < total; i++) {
      timeline = appendStep(timeline, makeSnapshot(i, 0x401000 + i)).timeline;
    }

    expect(timeline.steps).toHaveLength(MAX_STRIKE_TIMELINE_STEPS);
    expect(timeline.playheadIndex).toBe(MAX_STRIKE_TIMELINE_STEPS - 1);

    expect(timeline.steps[0].index).toBe(0);
    expect(timeline.steps[MAX_STRIKE_TIMELINE_STEPS - 1].index).toBe(MAX_STRIKE_TIMELINE_STEPS - 1);

    expect(timeline.steps[0].snapshot.stepCount).toBe(20);
    expect(timeline.steps[MAX_STRIKE_TIMELINE_STEPS - 1].snapshot.stepCount).toBe(total - 1);
  });
});
