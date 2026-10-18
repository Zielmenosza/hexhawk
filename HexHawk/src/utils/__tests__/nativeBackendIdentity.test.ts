import { beforeEach, describe, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { tauriBackend as engineBackend } from '../../engines/tauriBackend';
import { TauriNestBackend } from '../tauriNestBackend';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(async () => ({})) }));
const bridges = [{ name: 'engine', backend: engineBackend }, { name: 'NEST', backend: new TauriNestBackend() }];
beforeEach(() => vi.mocked(invoke).mockClear());
describe('native backend identity forwarding (mock transport, not native execution)', () => {
  for (const { name, backend } of bridges) {
    for (const [method, command] of [['disassembleRange', 'disassemble_file_range'], ['buildCfg', 'build_cfg']]) {
      it(`${name} ${method} carries the caller's inspected identity unchanged`, async () => {
        const sha = 'A'.repeat(64);
        await (backend as any)[method]('A.exe', 32, 16, sha);
        expect(invoke).toHaveBeenCalledWith(command, { path: 'A.exe', offset: 32, length: 16, expectedSha256: sha });
      });
      it(`${name} ${method} rejects an unbound request before native I/O`, async () => {
        await expect(Promise.resolve().then(() => (backend as any)[method]('A.exe',32,16))).rejects.toThrow(/inspected SHA-256/);
        expect(invoke).not.toHaveBeenCalled();
      });
    }
  }
});
