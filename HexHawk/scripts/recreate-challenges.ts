import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

interface ChallengeRecipe {
  id: string;
  sourceName: string;
  outputName: string;
  kind: 'linux' | 'windows' | 'portable';
  notes: string[];
  c: string;
  compile: string[];
  run?: string[];
}

const cwd = process.cwd();
const repoRoot = fs.existsSync(path.join(cwd, 'HexHawk', 'package.json')) ? cwd : path.resolve(cwd, '..');
const outRoot = path.resolve(process.argv[2] ?? path.join(repoRoot, 'work', 'recreate_challenges'));
const srcDir = path.join(outRoot, 'src');
const binDir = path.join(outRoot, 'bin');
const reportPath = path.join(outRoot, 'recreation_report.md');
fs.mkdirSync(srcDir, { recursive: true });
fs.mkdirSync(binDir, { recursive: true });

const banner = `       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐\n        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ \n        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘`;

function cstr(value: string): string {
  return JSON.stringify(value);
}

const pwnCommon = `#include <stdio.h>\n\nstatic void setup(void) {\n    setvbuf(stdout, NULL, _IONBF, 0);\n    setvbuf(stderr, NULL, _IONBF, 0);\n    setvbuf(stdin, NULL, _IONBF, 0);\n}\n\nstatic void banner(void) {\n    puts(${cstr(banner)});\n}\n`;

const recipes: ChallengeRecipe[] = [
  {
    id: 'pwn109',
    sourceName: 'Challenges/pwn109-1644300507645.pwn109',
    outputName: 'pwn109_recreated',
    kind: 'linux',
    notes: [
      'ELF64 dynamically linked, not stripped; main/setup/banner symbols are present.',
      'Objdump shows setup() sets stdin/stdout/stderr unbuffered, banner() puts ASCII art, main() allocates 0x20 bytes and calls gets(buffer).',
      'The long-input crash is intentional and preserved with gets() plus disabled stack protector/PIE.'
    ],
    c: `${pwnCommon}\nint main(void) {\n    char buf[32];\n    setup();\n    banner();\n    puts("                 pwn 109          \\n");\n    puts("This time no 🗑️ 🤫 & 🐈🚩.📄 Go ahead 😏");\n    gets(buf);\n}\n`,
    compile: ['wsl', '-e', 'sh', '-lc', 'cd /mnt/d/Project/HexHawk && gcc -fno-stack-protector -no-pie -fcf-protection=branch -Wno-implicit-function-declaration -o work/recreate_challenges/bin/pwn109_recreated work/recreate_challenges/src/pwn109_recreated.c'],
    run: ['wsl', '-e', 'sh', '-lc', 'cd /mnt/d/Project/HexHawk && printf "AAAA\\n" | ./work/recreate_challenges/bin/pwn109_recreated']
  },
  {
    id: 'pwn110',
    sourceName: 'Challenges/pwn110-1644300525386.pwn110',
    outputName: 'pwn110_recreated',
    kind: 'linux',
    notes: [
      'ELF64 statically linked; user-level main/setup/banner logic is the same vulnerable 32-byte stack buffer plus gets().',
      'Original differs mainly by static libc linkage and second prompt line; recreated binary is compiled static when WSL gcc supports it.'
    ],
    c: `${pwnCommon}\nint main(void) {\n    char buf[32];\n    setup();\n    banner();\n    puts("                 pwn 110          \\n");\n    puts("Hello pwner, I'm the last challenge 😼");\n    puts("Well done, Now try to pwn me without libc 😏");\n    gets(buf);\n}\n`,
    compile: ['wsl', '-e', 'sh', '-lc', 'cd /mnt/d/Project/HexHawk && gcc -static -fno-stack-protector -no-pie -fcf-protection=branch -Wno-implicit-function-declaration -o work/recreate_challenges/bin/pwn110_recreated work/recreate_challenges/src/pwn110_recreated.c'],
    run: ['wsl', '-e', 'sh', '-lc', 'cd /mnt/d/Project/HexHawk && printf "AAAA\\n" | ./work/recreate_challenges/bin/pwn110_recreated']
  },
  {
    id: 'crackme_shroud',
    sourceName: 'Challenges/crackme_shroud.exe',
    outputName: 'crackme_shroud_recreated.exe',
    kind: 'windows',
    notes: [
      'Observed execution: no argument prints usage and exits 1; wrong argument prints Access Denied and exits 1.',
      'HexHawk/NEST prior evidence flags anti-debug/dynamic-load/timing-check packer behavior. This safe recreation preserves CLI behavior and inserts inert timing/anti-debug-shaped branches without payload.'
    ],
    c: `#include <stdio.h>\n#include <string.h>\n#include <windows.h>\n\nint main(int argc, char **argv) {\n    LARGE_INTEGER a, b, f;\n    QueryPerformanceFrequency(&f);\n    QueryPerformanceCounter(&a);\n    if (argc != 2) {\n        printf("Usage: %s <password>\\r\\n", argv[0]);\n        return 1;\n    }\n    QueryPerformanceCounter(&b);\n    if (IsDebuggerPresent() || (b.QuadPart - a.QuadPart) > f.QuadPart) {\n        puts("Access Denied.\\r");\n        return 1;\n    }\n    if (strcmp(argv[1], "FLARE-ON-SHROUD") == 0) {\n        puts("Access Granted.\\r");\n        return 0;\n    }\n    puts("Access Denied.\\r");\n    return 1;\n}\n`,
    compile: ['x86_64-w64-mingw32-gcc', '-O2', '-o', path.join(binDir, 'crackme_shroud_recreated.exe'), path.join(srcDir, 'crackme_shroud_recreated.c')],
    run: [path.join(binDir, 'crackme_shroud_recreated.exe'), 'AAAA']
  },
  {
    id: 'project_chimera',
    sourceName: 'Challenges/2 - project_chimera/project_chimera.py',
    outputName: 'project_chimera_recreated.exe',
    kind: 'windows',
    notes: [
      'Original Python file contains a syntax error in the final nested f-string on Python 3.11/3.13, so observed execution aborts before payload execution.',
      'Static unpacking confirms zlib+marshal+exec staging. This recreation emits the visible journal boot message then reports the same syntax blocker safely.'
    ],
    c: `#include <stdio.h>\nint main(void) {\n    puts("Booting up Project Chimera from Dr. Khem's journal...");\n    fputs("SyntaxError: f-string: expecting '}' at project_chimera.py:30\\n", stderr);\n    return 1;\n}\n`,
    compile: ['x86_64-w64-mingw32-gcc', '-O2', '-o', path.join(binDir, 'project_chimera_recreated.exe'), path.join(srcDir, 'project_chimera_recreated.c')],
    run: [path.join(binDir, 'project_chimera_recreated.exe')]
  },
  {
    id: 'challenge_family_safe_stub',
    sourceName: 'Challenges/{ntfsm,hopeanddreams,FlareAuthenticator,keygenme,Gujian3,UnholyDragon,10000,chat_client}',
    outputName: 'challenge_family_safe_stub.exe',
    kind: 'windows',
    notes: [
      'For GUI/packed/very-large samples, execution either produced no terminal output, timed out, or is unsafe to let run freely on the host.',
      'This C recreation is a safe behavioral harness: it exposes the major HexHawk/NEST evidence families (crypto/wiper, RAT/system-enum/network, Qt authenticator/packed payload, process-injection loader, PyInstaller-like bundled dropper) without performing destructive/network actions.'
    ],
    c: `#include <stdio.h>\n#include <string.h>\n\nint main(int argc, char **argv) {\n    const char *mode = argc > 1 ? argv[1] : "summary";\n    if (strcmp(mode, "ntfsm") == 0) puts("ntfsm: BCrypt/OpenAlgorithm + decrypt + process execution + reboot path (simulated)");\n    else if (strcmp(mode, "hopeanddreams") == 0) puts("hopeanddreams: collect computer/user/system info + network client path (simulated)");\n    else if (strcmp(mode, "flareauth") == 0) puts("FlareAuthenticator: Qt login UI + encrypted .data payload + TLS callback shape (simulated)");\n    else if (strcmp(mode, "keygenme") == 0) puts("keygenme: CreateProcess suspended + resource extraction + VirtualAllocEx/WriteProcessMemory/CreateRemoteThread shape (simulated)");\n    else if (strcmp(mode, "chat_client") == 0) puts("chat_client: bundled ELF/PyInstaller-like client waits for chain-of-demands runtime inputs (simulated)");\n    else puts("Challenge-family safe recreation: pass ntfsm|hopeanddreams|flareauth|keygenme|chat_client for a specific simulated behavior.");\n    return 0;\n}\n`,
    compile: ['x86_64-w64-mingw32-gcc', '-O2', '-o', path.join(binDir, 'challenge_family_safe_stub.exe'), path.join(srcDir, 'challenge_family_safe_stub.c')],
    run: [path.join(binDir, 'challenge_family_safe_stub.exe'), 'ntfsm']
  }
];

function run(cmd: string[]): { ok: boolean; output: string } {
  const p = spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', timeout: 30000, shell: false });
  return { ok: p.status === 0, output: `cmd: ${cmd.join(' ')}\nexit: ${p.status}\nstdout:\n${p.stdout ?? ''}\nstderr:\n${p.stderr ?? ''}` };
}

const report: string[] = [];
report.push('# Challenge C recreation report');
report.push('');
report.push(`Generated: ${new Date().toISOString()}`);
report.push(`Output root: ${outRoot}`);
report.push('');

for (const recipe of recipes) {
  const cBaseName = recipe.outputName.replace(/\.exe$/i, '');
  const cPath = path.join(srcDir, `${cBaseName}.c`);
  fs.writeFileSync(cPath, recipe.c, 'utf8');
  report.push(`## ${recipe.id}`);
  report.push(`Original: ${recipe.sourceName}`);
  report.push(`Recreated C: ${cPath}`);
  report.push('Notes:');
  for (const note of recipe.notes) report.push(`- ${note}`);
  const compileResult = run(recipe.compile);
  report.push('Compile result:');
  report.push('```');
  report.push(compileResult.output.trim());
  report.push('```');
  if (recipe.run) {
    const runResult = run(recipe.run);
    report.push('Smoke run result:');
    report.push('```');
    report.push(runResult.output.trim());
    report.push('```');
  }
  report.push('');
}

fs.writeFileSync(reportPath, report.join('\n'), 'utf8');
console.log(`Wrote ${recipes.length} recreation source file(s) under ${srcDir}`);
console.log(`Report: ${reportPath}`);
