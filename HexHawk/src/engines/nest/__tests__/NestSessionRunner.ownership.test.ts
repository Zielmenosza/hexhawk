import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NestSessionRunner, runNestSession } from '../NestSessionRunner';
import { NestSessionRunner as CoreRunner, type NestRunnerOptions } from '../../../utils/nestRunner';
import { DEFAULT_NEST_CONFIG } from '../../../utils/nestEngine';
import type { NestBackend, DisassemblyResult } from '../../../utils/nestBackend';
import type { CfgGraph } from '../../../utils/cfgSignalExtractor';
import type { FileMetadata } from '../../../App';
import * as learning from '../../../utils/learningStore';
import * as dominance from '../../../utils/dominanceEngine';
import * as training from '../../../utils/nestTrainingStore';

// Real core, wrapper, analysis, and stores. Only backend transport and storage
// are inert fixtures; spies call through so successful persistence is read back.
const metadata: FileMetadata = {
  file_type: 'PE', architecture: 'x86_64', entry_point: 4096,
  file_size: 8192, image_base: 0, sections: [], imports_count: 0,
  exports_count: 0, symbols_count: 0, imports: [], exports: [],
  sha256: 'a'.repeat(64), sha1: 'b'.repeat(40), md5: 'c'.repeat(32),
};
const instructions = [{ address: 4096, mnemonic: 'ret', operands: '' }];
const graph: CfgGraph = { nodes: [{ id: 'entry', start: 4096 }], edges: [] };
const disasm: DisassemblyResult = { arch: 'x86_64', is_fallback: false, instructions };
const config = { ...DEFAULT_NEST_CONFIG, maxIterations: 1 };
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function backend(): NestBackend {
  return {
    buildCfg: vi.fn(async () => graph),
    disassembleRange: vi.fn(async () => disasm),
    inspectMetadata: vi.fn(async () => metadata),
    extractStrings: vi.fn(async () => []),
    identifyFormat: vi.fn(async () => ({ format: 'PE', magic_hex: '4d5a', file_size: 8192, entropy_header_4kb: 0 })),
  };
}
function options(b: NestBackend, shouldStop = () => false): NestRunnerOptions {
  return {
    filePath: 'inert-fixture.exe', config, backend: b, metadata,
    initialDisassembly: instructions, initialOffset: 4096, initialLength: 16,
    strings: [], shouldStop,
    disassemblyAnalysis: {
      functions: new Map(), suspiciousPatterns: [], loops: [],
      referenceStrength: new Map(), blockAnalysis: new Map(),
    },
  };
}
let stored: Map<string, string>;
let writes: ReturnType<typeof vi.fn>;
let sinks: ReturnType<typeof vi.spyOn>[];
beforeEach(() => {
  stored = new Map([['unrelated-fixture', 'unchanged']]);
  writes = vi.fn((key: string, value: string) => { stored.set(key, value); });
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: writes,
    removeItem: (key: string) => { stored.delete(key); },
    clear: () => stored.clear(),
  });
  sinks = [
    vi.spyOn(learning, 'saveLearningSession'),
    vi.spyOn(learning, 'recordStrategyOutcomes'),
    vi.spyOn(learning, 'recordBinarySession'),
    vi.spyOn(dominance, 'saveDominanceAssessment'),
    vi.spyOn(training, 'appendTrainingRecord'),
  ];
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });
function expectNoPersistence() {
  for (const sink of sinks) expect(sink).not.toHaveBeenCalled();
  expect(writes).not.toHaveBeenCalled();
  expect([...stored]).toEqual([['unrelated-fixture', 'unchanged']]);
}
async function expectStopped(pending: Promise<unknown>) {
  const outcome = await pending.then(() => ({ name: 'resolved' }), e => e);
  expectNoPersistence();
  expect(outcome).toMatchObject({ name: 'AbortError' });
}

describe('real NEST retained ownership', () => {
  for (const method of ['runOne', 'run'] as const) {
    for (const phase of ['cfg', 'expansion'] as const) {
      for (const settlement of ['resolve', 'reject'] as const) {
        it(`core ${method}: held ${phase} ${settlement} cannot advance after stop`, async () => {
          const b = backend();
          const entered = deferred<void>();
          const cfgHeld = deferred<CfgGraph>();
          const disasmHeld = deferred<DisassemblyResult>();
          if (phase === 'cfg') vi.mocked(b.buildCfg).mockImplementation(() => {
            entered.resolve(); return cfgHeld.promise;
          });
          else vi.mocked(b.disassembleRange).mockImplementation(() => {
            entered.resolve(); return disasmHeld.promise;
          });
          let stop = false;
          const onIteration = vi.fn();
          const getBoosts = vi.fn(() => null);
          const runner = new CoreRunner({ ...options(b, () => stop), onIteration, getBoosts });
          const pending = runner[method]();
          await entered.promise;
          const callbacksBeforeStop = onIteration.mock.calls.length;
          stop = true;
          if (phase === 'cfg') {
            if (settlement === 'resolve') cfgHeld.resolve(graph); else cfgHeld.reject(new Error('fixture failure'));
          } else {
            if (settlement === 'resolve') disasmHeld.resolve({ ...disasm, instructions: [{ address: 8192, mnemonic: 'nop', operands: '' }] });
            else disasmHeld.reject(new Error('fixture failure'));
          }
          await expectStopped(pending);
          expect(onIteration).toHaveBeenCalledTimes(callbacksBeforeStop);
          expect(callbacksBeforeStop).toBe(phase === 'cfg' ? 0 : 1);
          expect(getBoosts).toHaveBeenCalledTimes(phase === 'cfg' ? 0 : 1);
          expect(b.buildCfg).toHaveBeenCalledTimes(1);
          expect(b.disassembleRange).toHaveBeenCalledTimes(phase === 'cfg' ? 0 : 1);
          expect(runner.disassembly).toEqual(instructions);
          expect(runner.session.finalVerdict).toBeNull();
          expect(runner.learningSession.endTime).toBeNull();
        });
      }
    }
  }

  for (const method of ['step', 'run'] as const) {
    for (const settlement of ['resolve', 'reject'] as const) {
      it(`${method}: settles held CFG ${settlement} without stale learning, callbacks, or expansion`, async () => {
        const b = backend();
        const entered = deferred<void>();
        const held = deferred<CfgGraph>();
        vi.mocked(b.buildCfg).mockImplementation(() => { entered.resolve(); return held.promise; });
        let stop = false;
        const onIteration = vi.fn();
        const getBoosts = vi.fn(() => null);
        const runner = new NestSessionRunner({ ...options(b, () => stop), onIteration, getBoosts });
        const pending = runner[method]();
        let settled = false;
        void pending.then(() => { settled = true; }, () => { settled = true; });
        await entered.promise;
        stop = true;
        await Promise.resolve();
        expect(settled).toBe(false); // entered transport must retain settlement
        if (settlement === 'resolve') held.resolve(graph); else held.reject(new Error('fixture CFG failure'));
        await expectStopped(pending);
        expect(onIteration).not.toHaveBeenCalled();
        expect(getBoosts).not.toHaveBeenCalled();
        expect(b.disassembleRange).not.toHaveBeenCalled();
        expect(runner.session.iterations).toHaveLength(0);
        expect(runner.session.finalVerdict).toBeNull();
        expect(runner.learningSession.endTime).toBeNull();
      });
    }
  }

  for (const settlement of ['resolve', 'reject'] as const) {
    it(`run: does not publish or persist after held expansion ${settlement}`, async () => {
      const b = backend();
      const entered = deferred<void>();
      const held = deferred<DisassemblyResult>();
      vi.mocked(b.disassembleRange).mockImplementation(() => { entered.resolve(); return held.promise; });
      let stop = false;
      const onIteration = vi.fn();
      const runner = new NestSessionRunner({ ...options(b, () => stop), onIteration });
      const pending = runner.run();
      await entered.promise;
      stop = true;
      if (settlement === 'resolve') held.resolve({ ...disasm, instructions: [{ address: 8192, mnemonic: 'nop', operands: '' }] });
      else held.reject(new Error('fixture disassembly failure'));
      await expectStopped(pending);
      expect(onIteration).not.toHaveBeenCalled();
      expect(b.buildCfg).toHaveBeenCalledTimes(1);
      expect(b.disassembleRange).toHaveBeenCalledTimes(1);
      expect(runner.disassembly).toEqual(instructions);
      expect(runner.session.finalVerdict).toBeNull();
    });
  }

  for (const method of ['step', 'run'] as const) {
    it(`${method}: a pre-stopped runner has no backend, boost, callback, or store side effects`, async () => {
      const b = backend();
      const onIteration = vi.fn();
      const getBoosts = vi.fn(() => null);
      const runner = new NestSessionRunner({ ...options(b, () => true), onIteration, getBoosts });
      await expectStopped(runner[method]());
      expect(b.buildCfg).not.toHaveBeenCalled();
      expect(b.disassembleRange).not.toHaveBeenCalled();
      expect(getBoosts).not.toHaveBeenCalled();
      expect(onIteration).not.toHaveBeenCalled();
      expect(runner.session.finalVerdict).toBeNull();
    });
  }

  it('a core onIteration stop cannot admit expansion or synthesize convergence', async () => {
    const b = backend();
    let stop = false;
    const onIteration = vi.fn(() => { stop = true; });
    const runner = new CoreRunner({ ...options(b, () => stop), onIteration });
    await expectStopped(runner.run());
    expect(onIteration).toHaveBeenCalledTimes(1); // published while still owned
    expect(b.disassembleRange).not.toHaveBeenCalled();
    expect(runner.session.finalVerdict).toBeNull();
    expect(runner.session.endTime).toBeNull();
  });

  it('a getBoosts stop cannot publish or begin another phase', async () => {
    const b = backend();
    let stop = false;
    const onIteration = vi.fn();
    const runner = new NestSessionRunner({
      ...options(b, () => stop), onIteration,
      getBoosts: () => { stop = true; return null; },
    });
    await expectStopped(runner.run());
    expect(onIteration).not.toHaveBeenCalled();
    expect(b.disassembleRange).not.toHaveBeenCalled();
  });

  it('stopping between iterations does not run unconditional post-processing', async () => {
    vi.useFakeTimers();
    const b = backend();
    let stop = false;
    const onIteration = vi.fn();
    const runner = new NestSessionRunner({ ...options(b, () => stop), onIteration });
    const pending = runner.run(100);
    const stopped = expectStopped(pending); // attach before the fake timer rejects
    // Advance microtasks until the completed first iteration reaches its delay.
    await vi.advanceTimersByTimeAsync(0);
    expect(onIteration).toHaveBeenCalledTimes(1);
    expect(b.buildCfg).toHaveBeenCalledTimes(1);
    stop = true;
    await vi.advanceTimersByTimeAsync(100);
    await stopped;
    expect(b.buildCfg).toHaveBeenCalledTimes(1);
    expect(runner.session.finalVerdict).toBeNull();
  });

  for (const phase of ['metadata', 'disassembly'] as const) {
    for (const settlement of ['resolve', 'reject'] as const) {
      it(`entrypoint: stops after held ${phase} ${settlement} without admitting the next phase`, async () => {
        const b = backend();
        const entered = deferred<void>();
        const held = deferred<FileMetadata | DisassemblyResult>();
        if (phase === 'metadata') vi.mocked(b.inspectMetadata).mockImplementation(async () => {
          entered.resolve(); return await held.promise as FileMetadata;
        });
        else vi.mocked(b.disassembleRange).mockImplementation(async () => {
          entered.resolve(); return await held.promise as DisassemblyResult;
        });
        let stop = false;
        const onIteration = vi.fn();
        const pending = runNestSession('inert-fixture.exe', config, {
          backend: b, shouldStop: () => stop, onIteration,
          metadata: phase === 'metadata' ? undefined : metadata,
        });
        await entered.promise;
        stop = true;
        if (settlement === 'resolve') held.resolve(phase === 'metadata' ? metadata : disasm);
        else held.reject(new Error('fixture transport failure'));
        await expectStopped(pending);
        expect(b.buildCfg).not.toHaveBeenCalled();
        expect(b.disassembleRange).toHaveBeenCalledTimes(phase === 'metadata' ? 0 : 1);
        expect(onIteration).not.toHaveBeenCalled();
      });
    }
  }

  it('a pre-stopped entrypoint does not fetch metadata or disassembly', async () => {
    const b = backend();
    await expectStopped(runNestSession('inert-fixture.exe', config, { backend: b, shouldStop: () => true }));
    expect(b.inspectMetadata).not.toHaveBeenCalled();
    expect(b.disassembleRange).not.toHaveBeenCalled();
  });

  it('valid standalone completion still persists real learning and training exactly once', async () => {
    const b = backend();
    const onIteration = vi.fn();
    const runner = new NestSessionRunner({ ...options(b), onIteration });
    const result = await runner.run();
    expect(result.session.status).toBe('max-reached');
    expect(result.session.finalVerdict).not.toBeNull();
    expect(onIteration).toHaveBeenCalledTimes(result.session.iterations.length);
    for (const sink of sinks) expect(sink).toHaveBeenCalledTimes(1);
    expect(learning.getLearningRecord(metadata.sha256)?.sessionCount).toBe(1);
    expect(training.getRecentRecords(50)).toHaveLength(1);
    expect(result.trainingRecords[0].id).toBe(result.session.id);
    expect(writes).toHaveBeenCalled();
  });

  it('valid standalone step completion still supplies and persists post-processing', async () => {
    const runner = new NestSessionRunner(options(backend()));
    expect((await runner.step()).shouldContinue).toBe(true);
    expectNoPersistence();
    const terminal = await runner.step();
    expect(terminal.shouldContinue).toBe(false);
    expect(terminal.postProcessing?.learningRecord?.hash).toBe(metadata.sha256);
    expect(training.getRecentRecords(50)[0].id).toBe(runner.session.id);
    for (const sink of sinks) expect(sink).toHaveBeenCalledTimes(1);
    expect(runner.commitPostProcessing()).toBe(terminal.postProcessing);
    for (const sink of sinks) expect(sink).toHaveBeenCalledTimes(1);
  });

  for (const losesOwner of [false, true]) {
    it(`deferred learning commit after native settlement: ownership lost=${losesOwner}`, async () => {
      let stop = false;
      const runner = new NestSessionRunner({
        ...options(backend(), () => stop), deferStepPostProcessing: true,
      });
      await runner.step();
      const terminal = await runner.step();
      expect(terminal.shouldContinue).toBe(false);
      expect(terminal.postProcessing).toBeUndefined();
      expectNoPersistence();
      // Fixture for entered native append/finalize: settlement is retained, but
      // it cannot itself authorize learning when the selection no longer owns it.
      const nativeSettlement = deferred<void>();
      const commit = nativeSettlement.promise.then(() => runner.commitPostProcessing());
      stop = losesOwner;
      expectNoPersistence();
      nativeSettlement.resolve();
      if (losesOwner) await expectStopped(commit);
      else {
        const result = await commit;
        expect(result.learningRecord?.sessionCount).toBe(1);
        expect(training.getRecentRecords(50)[0].id).toBe(runner.session.id);
        expect(runner.commitPostProcessing()).toBe(result);
        for (const sink of sinks) expect(sink).toHaveBeenCalledTimes(1);
      }
    });
  }

  it('deferred learning cannot commit an incomplete session', async () => {
    const runner = new NestSessionRunner({ ...options(backend()), deferStepPostProcessing: true });
    expect(() => runner.commitPostProcessing()).toThrow('completed session');
    await runner.step();
    expect(() => runner.commitPostProcessing()).toThrow('completed session');
    expectNoPersistence();
  });

  it('the wrapper rechecks ownership in the await gap before post-processing', async () => {
    let stop = false;
    let boostCalls = 0;
    const onIteration = vi.fn();
    const runner = new NestSessionRunner({
      ...options(backend(), () => stop),
      getBoosts: () => {
        if (++boostCalls === 2) queueMicrotask(() => { stop = true; });
        return null;
      },
      onIteration,
    });
    expect((await runner.step()).shouldContinue).toBe(true);
    expectNoPersistence();
    await expectStopped(runner.step());
    expect(boostCalls).toBe(2);
    expect(runner.session.status).toBe('max-reached'); // core completed while owned
    expect(onIteration).toHaveBeenCalledTimes(1); // stale final result not published
  });

  for (const method of ['step', 'run'] as const) {
    it(`${method}: stale terminal CFG cannot persist accumulated strategy outcomes`, async () => {
      const b = backend();
      const entered = deferred<void>();
      const held = deferred<CfgGraph>();
      vi.mocked(b.buildCfg).mockImplementationOnce(async () => graph)
        .mockImplementationOnce(() => { entered.resolve(); return held.promise; });
      let stop = false;
      const onIteration = vi.fn();
      const runner = new NestSessionRunner({ ...options(b, () => stop), onIteration });
      const first = await runner.step();
      expect(first.shouldContinue).toBe(true);
      const before = runner.learningSession;
      const pending = runner[method]();
      await entered.promise;
      expectNoPersistence();
      stop = true;
      held.resolve(graph);
      await expectStopped(pending);
      expect(runner.learningSession).toBe(before);
      expect(runner.session.iterations).toHaveLength(1);
      expect(runner.session.finalVerdict).toBeNull();
      expect(onIteration).toHaveBeenCalledTimes(1);
      expect(b.disassembleRange).toHaveBeenCalledTimes(1);
    });
  }

  it('an intentional stop can be cleared to resume without a fabricated terminal session', async () => {
    const b = backend();
    const entered = deferred<void>();
    const held = deferred<CfgGraph>();
    vi.mocked(b.buildCfg).mockImplementationOnce(() => { entered.resolve(); return held.promise; });
    let stop = false;
    const runner = new NestSessionRunner(options(b, () => stop));
    const pending = runner.step();
    await entered.promise;
    stop = true;
    held.resolve(graph);
    await expectStopped(pending);
    expect(runner.session.iterations).toHaveLength(0);
    stop = false;
    const result = await runner.run();
    expect(result.session.status).toBe('max-reached');
    expect(learning.getLearningRecord(metadata.sha256)?.sessionCount).toBe(1);
    expect(training.getRecentRecords(50)).toHaveLength(1);
  });
});
