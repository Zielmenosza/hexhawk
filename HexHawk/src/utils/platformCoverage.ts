export type PlatformCoverageStatus =
  | 'proof-backed'
  | 'metadata-detectable'
  | 'planned-adapter'
  | 'research-needed';

export type PlatformEra = '1970s' | '1980s' | '1990s' | '2000s' | '2010s' | '2020s';

export type PlatformDomain =
  | 'microcomputer'
  | 'minicomputer'
  | 'mainframe'
  | 'workstation'
  | 'desktop'
  | 'server'
  | 'embedded'
  | 'mobile'
  | 'firmware'
  | 'virtual-machine'
  | 'network-capture'
  | 'document-container'
  | 'archive-container';

export interface PlatformCoverageTarget {
  id: string;
  label: string;
  era: PlatformEra;
  domains: PlatformDomain[];
  architectures: string[];
  executableFormats: string[];
  commonExtensions: string[];
  detectionSignals: string[];
  firstUtilityMilestone: string;
  status: PlatformCoverageStatus;
  authorityBoundary: string;
}

const SUPPORT_BOUNDARY = 'Coverage registry is a roadmap and detection aid. It does not claim full parser, disassembler, decompiler, or verdict correctness support.';

export const PLATFORM_COVERAGE_TARGETS: PlatformCoverageTarget[] = [
  {
    id: 'intel-hex-srec-1970s-microcontrollers',
    label: 'Intel HEX / Motorola S-record microcontroller images',
    era: '1970s',
    domains: ['embedded', 'firmware', 'microcomputer'],
    architectures: ['Intel 8080', 'Intel 8048', 'Motorola 6800', 'MOS 6502', 'Zilog Z80'],
    executableFormats: ['Intel HEX', 'Motorola S-record', 'raw ROM image'],
    commonExtensions: ['.hex', '.ihex', '.s19', '.s28', '.s37', '.bin', '.rom'],
    detectionSignals: ['colon-prefixed Intel HEX records', 'S-record line prefixes', 'small flat ROM image', 'reset vector heuristics'],
    firstUtilityMilestone: 'Identify record format, checksum records, map address ranges, and extract printable strings without executing content.',
    status: 'planned-adapter',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'cp-m-dos-com-1970s-1980s',
    label: 'CP/M and DOS COM flat binaries',
    era: '1970s',
    domains: ['microcomputer', 'desktop'],
    architectures: ['Intel 8080', 'Zilog Z80', 'Intel 8086', 'Intel 8088'],
    executableFormats: ['CP/M COM', 'DOS COM', 'flat binary'],
    commonExtensions: ['.com', '.bin'],
    detectionSignals: ['extension and small flat image', 'ORG 100h DOS convention', 'CP/M BDOS call patterns'],
    firstUtilityMilestone: 'Offer flat-binary load profiles with selectable base address and architecture hints.',
    status: 'research-needed',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'aout-coff-1980s-unix',
    label: 'Early UNIX a.out and COFF executables',
    era: '1980s',
    domains: ['minicomputer', 'workstation', 'server'],
    architectures: ['PDP-11', 'VAX', 'Motorola 68000', 'Intel 80386', 'MIPS I'],
    executableFormats: ['a.out', 'COFF', 'ECOFF'],
    commonExtensions: ['', '.o', '.obj', '.out'],
    detectionSignals: ['a.out magic values', 'COFF file header', 'section table', 'symbol table'],
    firstUtilityMilestone: 'Parse headers/sections/symbols and expose architecture/endian hints before disassembly.',
    status: 'planned-adapter',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'classic-mac-amiga-atari-1980s',
    label: 'Classic Mac/Amiga/Atari application and resource containers',
    era: '1980s',
    domains: ['desktop', 'microcomputer'],
    architectures: ['Motorola 68000', 'PowerPC'],
    executableFormats: ['Classic Mac resource fork', 'Amiga HUNK', 'Atari PRG/TOS'],
    commonExtensions: ['.prg', '.tos', '.hunk', '.rsrc'],
    detectionSignals: ['HUNK magic', 'TOS header hints', 'resource map structures', '68k vector/code patterns'],
    firstUtilityMilestone: 'Detect container family and present resource/code segmentation without claiming full decompilation.',
    status: 'research-needed',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'pe-elf-mach-o-1990s-present',
    label: 'PE/COFF, ELF, and Mach-O native executables',
    era: '1990s',
    domains: ['desktop', 'server', 'mobile', 'embedded'],
    architectures: ['x86', 'x86-64', 'ARM', 'AArch64', 'MIPS', 'PowerPC', 'SPARC', 'RISC-V'],
    executableFormats: ['PE/COFF', 'ELF', 'Mach-O', 'fat/universal Mach-O'],
    commonExtensions: ['.exe', '.dll', '.sys', '.so', '.dylib', '.app', '.o'],
    detectionSignals: ['MZ/PE header', 'ELF magic', 'Mach-O magic/fat magic', 'section/program headers', 'imports/exports'],
    firstUtilityMilestone: 'Keep existing PE proof-backed path, then add ELF/Mach-O parser parity and architecture-specific disassembly profiles.',
    status: 'proof-backed',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'java-dotnet-vm-1990s-2000s',
    label: 'Managed VM bytecode: Java class/JAR and .NET assemblies',
    era: '1990s',
    domains: ['desktop', 'server', 'mobile', 'virtual-machine'],
    architectures: ['JVM bytecode', 'CIL/MSIL'],
    executableFormats: ['Java class', 'JAR', '.NET PE assembly', 'CLI metadata'],
    commonExtensions: ['.class', '.jar', '.war', '.ear', '.exe', '.dll'],
    detectionSignals: ['CAFEBABE class magic', 'ZIP/JAR manifest', 'CLI metadata directory', 'managed imports'],
    firstUtilityMilestone: 'Detect managed runtime metadata and route to bytecode/metadata views rather than native-only assumptions.',
    status: 'planned-adapter',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'mobile-console-2000s-2010s',
    label: 'Mobile and console-era packages',
    era: '2000s',
    domains: ['mobile', 'embedded', 'archive-container'],
    architectures: ['ARM', 'Thumb', 'AArch64', 'MIPS', 'PowerPC', 'Dalvik bytecode'],
    executableFormats: ['APK/DEX', 'IPA/Mach-O', 'ELF firmware payload', 'console package/container'],
    commonExtensions: ['.apk', '.dex', '.ipa', '.xex', '.self', '.pkg', '.nso'],
    detectionSignals: ['DEX magic', 'APK ZIP manifest', 'Mach-O in IPA', 'ELF payloads inside containers'],
    firstUtilityMilestone: 'Unpack safely with size budgets, detect bytecode/native payloads, and preserve container provenance.',
    status: 'planned-adapter',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'firmware-uefi-iot-2000s-present',
    label: 'Firmware, UEFI, router, and IoT images',
    era: '2000s',
    domains: ['firmware', 'embedded', 'archive-container'],
    architectures: ['ARM', 'MIPS', 'PowerPC', 'x86', 'AArch64', 'RISC-V'],
    executableFormats: ['UEFI PEI/DXE PE', 'raw flash image', 'uImage', 'squashfs/cramfs payload', 'FIT image'],
    commonExtensions: ['.fd', '.rom', '.bin', '.img', '.trx', '.uimage', '.fit'],
    detectionSignals: ['UEFI firmware volume signatures', 'uImage magic', 'filesystem magic', 'embedded ELF/PE payloads'],
    firstUtilityMilestone: 'Layered container scan: identify partitions/filesystems/payloads and apply explicit extraction budgets.',
    status: 'planned-adapter',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'documents-archives-network-1990s-present',
    label: 'Documents, archives, and network captures as analysis containers',
    era: '1990s',
    domains: ['document-container', 'archive-container', 'network-capture'],
    architectures: ['container', 'script', 'macro', 'packet data'],
    executableFormats: ['PDF', 'OLE/Office', 'OOXML', 'ZIP/7z/RAR', 'PCAP/PCAPNG'],
    commonExtensions: ['.pdf', '.doc', '.docm', '.docx', '.xls', '.xlsx', '.zip', '.7z', '.rar', '.pcap', '.pcapng'],
    detectionSignals: ['PDF header', 'OLE magic', 'ZIP local headers', '7z magic', 'pcap/pcapng magic'],
    firstUtilityMilestone: 'Continue safe metadata/string/hash extraction with decompression and stream-size budgets before deep parsing.',
    status: 'metadata-detectable',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'modern-cloud-runtime-2010s-2020s',
    label: 'Modern cloud/runtime artifacts: WASM, eBPF, containers, scripts',
    era: '2010s',
    domains: ['server', 'virtual-machine', 'embedded', 'archive-container'],
    architectures: ['WebAssembly', 'eBPF', 'LLVM bitcode', 'Python bytecode', 'JavaScript bundles'],
    executableFormats: ['WASM module', 'eBPF object', 'OCI layer', 'script bundle', 'LLVM bitcode'],
    commonExtensions: ['.wasm', '.o', '.bc', '.pyc', '.js', '.mjs', '.tar', '.tgz'],
    detectionSignals: ['WASM magic', 'ELF eBPF machine type', 'LLVM bitcode wrapper', 'PYC magic', 'OCI layer metadata'],
    firstUtilityMilestone: 'Detect runtime family, list imports/exports/sections, and route to bytecode/container-specific views.',
    status: 'planned-adapter',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
  {
    id: 'riscv-and-post-2020-platforms',
    label: 'RISC-V and newer post-2020 platform targets',
    era: '2020s',
    domains: ['embedded', 'server', 'firmware'],
    architectures: ['RISC-V 32', 'RISC-V 64', 'CHERI-derived research targets'],
    executableFormats: ['ELF', 'firmware image', 'raw ROM image'],
    commonExtensions: ['.elf', '.so', '.bin', '.img', '.rom'],
    detectionSignals: ['ELF e_machine RISC-V', 'RISC-V instruction bit patterns', 'firmware container context'],
    firstUtilityMilestone: 'Add architecture-profile hints and Capstone/object parser capability checks before claiming disassembly parity.',
    status: 'planned-adapter',
    authorityBoundary: SUPPORT_BOUNDARY,
  },
];

export function getPlatformCoverageInventory(): PlatformCoverageTarget[] {
  return PLATFORM_COVERAGE_TARGETS.map((target) => ({
    ...target,
    domains: [...target.domains],
    architectures: [...target.architectures],
    executableFormats: [...target.executableFormats],
    commonExtensions: [...target.commonExtensions],
    detectionSignals: [...target.detectionSignals],
  }));
}

export function summarizeEraCoverage(targets: PlatformCoverageTarget[] = PLATFORM_COVERAGE_TARGETS): Record<PlatformEra, number> {
  return targets.reduce((summary, target) => {
    summary[target.era] = (summary[target.era] ?? 0) + 1;
    return summary;
  }, {} as Record<PlatformEra, number>);
}

export function findCoverageTargets(query: string, targets: PlatformCoverageTarget[] = PLATFORM_COVERAGE_TARGETS): PlatformCoverageTarget[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return getPlatformCoverageInventory();

  return targets
    .filter((target) => [
      target.id,
      target.label,
      target.era,
      ...target.domains,
      ...target.architectures,
      ...target.executableFormats,
      ...target.commonExtensions,
      ...target.detectionSignals,
      target.firstUtilityMilestone,
      target.status,
    ].some((value) => value.toLowerCase().includes(needle)))
    .map((target) => ({
      ...target,
      domains: [...target.domains],
      architectures: [...target.architectures],
      executableFormats: [...target.executableFormats],
      commonExtensions: [...target.commonExtensions],
      detectionSignals: [...target.detectionSignals],
    }));
}

export function hasUnsupportedClaim(target: PlatformCoverageTarget): boolean {
  if (target.status === 'proof-backed') return false;
  const milestone = target.firstUtilityMilestone.toLowerCase();
  const boundaryAwareNegation = /without claiming full|does not claim full|no full|not full/.test(milestone);
  if (boundaryAwareNegation) return false;
  return /full parser|full decompil|complete support|release-ready|verdict correctness/.test(milestone);
}
