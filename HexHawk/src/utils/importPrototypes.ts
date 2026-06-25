export interface ImportParameterPrototype {
  name: string;
  type: string;
}

export interface ImportPrototype {
  library: 'kernel32' | 'ntdll' | 'user32' | 'libc';
  name: string;
  returnType: string;
  parameters: ImportParameterPrototype[];
  callingConvention?: 'winapi' | 'ntapi' | 'cdecl';
}

const p = (name: string, type: string): ImportParameterPrototype => ({ name, type });

export const IMPORT_PROTOTYPES = [
  { library: 'kernel32', name: 'CreateFileW', returnType: 'HANDLE', callingConvention: 'winapi', parameters: [p('lpFileName', 'LPCWSTR'), p('dwDesiredAccess', 'DWORD'), p('dwShareMode', 'DWORD'), p('lpSecurityAttributes', 'LPSECURITY_ATTRIBUTES'), p('dwCreationDisposition', 'DWORD'), p('dwFlagsAndAttributes', 'DWORD'), p('hTemplateFile', 'HANDLE')] },
  { library: 'kernel32', name: 'CreateFileA', returnType: 'HANDLE', callingConvention: 'winapi', parameters: [p('lpFileName', 'LPCSTR'), p('dwDesiredAccess', 'DWORD'), p('dwShareMode', 'DWORD'), p('lpSecurityAttributes', 'LPSECURITY_ATTRIBUTES'), p('dwCreationDisposition', 'DWORD'), p('dwFlagsAndAttributes', 'DWORD'), p('hTemplateFile', 'HANDLE')] },
  { library: 'kernel32', name: 'ReadFile', returnType: 'BOOL', callingConvention: 'winapi', parameters: [p('hFile', 'HANDLE'), p('lpBuffer', 'LPVOID'), p('nNumberOfBytesToRead', 'DWORD'), p('lpNumberOfBytesRead', 'LPDWORD'), p('lpOverlapped', 'LPOVERLAPPED')] },
  { library: 'kernel32', name: 'WriteFile', returnType: 'BOOL', callingConvention: 'winapi', parameters: [p('hFile', 'HANDLE'), p('lpBuffer', 'LPCVOID'), p('nNumberOfBytesToWrite', 'DWORD'), p('lpNumberOfBytesWritten', 'LPDWORD'), p('lpOverlapped', 'LPOVERLAPPED')] },
  { library: 'kernel32', name: 'CloseHandle', returnType: 'BOOL', callingConvention: 'winapi', parameters: [p('hObject', 'HANDLE')] },
  { library: 'kernel32', name: 'VirtualAlloc', returnType: 'LPVOID', callingConvention: 'winapi', parameters: [p('lpAddress', 'LPVOID'), p('dwSize', 'SIZE_T'), p('flAllocationType', 'DWORD'), p('flProtect', 'DWORD')] },
  { library: 'kernel32', name: 'VirtualFree', returnType: 'BOOL', callingConvention: 'winapi', parameters: [p('lpAddress', 'LPVOID'), p('dwSize', 'SIZE_T'), p('dwFreeType', 'DWORD')] },
  { library: 'kernel32', name: 'VirtualProtect', returnType: 'BOOL', callingConvention: 'winapi', parameters: [p('lpAddress', 'LPVOID'), p('dwSize', 'SIZE_T'), p('flNewProtect', 'DWORD'), p('lpflOldProtect', 'PDWORD')] },
  { library: 'kernel32', name: 'GetProcAddress', returnType: 'FARPROC', callingConvention: 'winapi', parameters: [p('hModule', 'HMODULE'), p('lpProcName', 'LPCSTR')] },
  { library: 'kernel32', name: 'LoadLibraryW', returnType: 'HMODULE', callingConvention: 'winapi', parameters: [p('lpLibFileName', 'LPCWSTR')] },
  { library: 'kernel32', name: 'LoadLibraryA', returnType: 'HMODULE', callingConvention: 'winapi', parameters: [p('lpLibFileName', 'LPCSTR')] },
  { library: 'kernel32', name: 'GetLastError', returnType: 'DWORD', callingConvention: 'winapi', parameters: [] },
  { library: 'kernel32', name: 'ExitProcess', returnType: 'VOID', callingConvention: 'winapi', parameters: [p('uExitCode', 'UINT')] },
  { library: 'ntdll', name: 'NtAllocateVirtualMemory', returnType: 'NTSTATUS', callingConvention: 'ntapi', parameters: [p('ProcessHandle', 'HANDLE'), p('BaseAddress', 'PVOID*'), p('ZeroBits', 'ULONG_PTR'), p('RegionSize', 'PSIZE_T'), p('AllocationType', 'ULONG'), p('Protect', 'ULONG')] },
  { library: 'ntdll', name: 'NtWriteVirtualMemory', returnType: 'NTSTATUS', callingConvention: 'ntapi', parameters: [p('ProcessHandle', 'HANDLE'), p('BaseAddress', 'PVOID'), p('Buffer', 'PVOID'), p('NumberOfBytesToWrite', 'ULONG'), p('NumberOfBytesWritten', 'PULONG')] },
  { library: 'ntdll', name: 'NtCreateFile', returnType: 'NTSTATUS', callingConvention: 'ntapi', parameters: [p('FileHandle', 'PHANDLE'), p('DesiredAccess', 'ACCESS_MASK'), p('ObjectAttributes', 'POBJECT_ATTRIBUTES'), p('IoStatusBlock', 'PIO_STATUS_BLOCK'), p('AllocationSize', 'PLARGE_INTEGER'), p('FileAttributes', 'ULONG'), p('ShareAccess', 'ULONG'), p('CreateDisposition', 'ULONG'), p('CreateOptions', 'ULONG'), p('EaBuffer', 'PVOID'), p('EaLength', 'ULONG')] },
  { library: 'ntdll', name: 'RtlAllocateHeap', returnType: 'PVOID', callingConvention: 'ntapi', parameters: [p('HeapHandle', 'PVOID'), p('Flags', 'ULONG'), p('Size', 'SIZE_T')] },
  { library: 'user32', name: 'MessageBoxW', returnType: 'int', callingConvention: 'winapi', parameters: [p('hWnd', 'HWND'), p('lpText', 'LPCWSTR'), p('lpCaption', 'LPCWSTR'), p('uType', 'UINT')] },
  { library: 'user32', name: 'MessageBoxA', returnType: 'int', callingConvention: 'winapi', parameters: [p('hWnd', 'HWND'), p('lpText', 'LPCSTR'), p('lpCaption', 'LPCSTR'), p('uType', 'UINT')] },
  { library: 'user32', name: 'CreateWindowExW', returnType: 'HWND', callingConvention: 'winapi', parameters: [p('dwExStyle', 'DWORD'), p('lpClassName', 'LPCWSTR'), p('lpWindowName', 'LPCWSTR'), p('dwStyle', 'DWORD'), p('X', 'int'), p('Y', 'int'), p('nWidth', 'int'), p('nHeight', 'int'), p('hWndParent', 'HWND'), p('hMenu', 'HMENU'), p('hInstance', 'HINSTANCE'), p('lpParam', 'LPVOID')] },
  { library: 'user32', name: 'SendMessageW', returnType: 'LRESULT', callingConvention: 'winapi', parameters: [p('hWnd', 'HWND'), p('Msg', 'UINT'), p('wParam', 'WPARAM'), p('lParam', 'LPARAM')] },
  { library: 'libc', name: 'malloc', returnType: 'void*', callingConvention: 'cdecl', parameters: [p('size', 'size_t')] },
  { library: 'libc', name: 'free', returnType: 'void', callingConvention: 'cdecl', parameters: [p('ptr', 'void*')] },
  { library: 'libc', name: 'memcpy', returnType: 'void*', callingConvention: 'cdecl', parameters: [p('dest', 'void*'), p('src', 'const void*'), p('n', 'size_t')] },
  { library: 'libc', name: 'memset', returnType: 'void*', callingConvention: 'cdecl', parameters: [p('s', 'void*'), p('c', 'int'), p('n', 'size_t')] },
  { library: 'libc', name: 'strlen', returnType: 'size_t', callingConvention: 'cdecl', parameters: [p('s', 'const char*')] },
  { library: 'libc', name: 'printf', returnType: 'int', callingConvention: 'cdecl', parameters: [p('format', 'const char*')] },
  { library: 'libc', name: 'fopen', returnType: 'FILE*', callingConvention: 'cdecl', parameters: [p('filename', 'const char*'), p('mode', 'const char*')] },
  { library: 'libc', name: 'fclose', returnType: 'int', callingConvention: 'cdecl', parameters: [p('stream', 'FILE*')] },
  { library: 'libc', name: 'fread', returnType: 'size_t', callingConvention: 'cdecl', parameters: [p('ptr', 'void*'), p('size', 'size_t'), p('nmemb', 'size_t'), p('stream', 'FILE*')] },
  { library: 'libc', name: 'fwrite', returnType: 'size_t', callingConvention: 'cdecl', parameters: [p('ptr', 'const void*'), p('size', 'size_t'), p('nmemb', 'size_t'), p('stream', 'FILE*')] },
  { library: 'libc', name: 'exit', returnType: 'void', callingConvention: 'cdecl', parameters: [p('status', 'int')] },
] as const satisfies readonly ImportPrototype[];


type ConstantAnnotationSpec = {
  values?: Record<number, string>;
  flags?: Array<{ value: number; name: string }>;
};

type ConstantAnnotationMap = Record<string, Record<number, ConstantAnnotationSpec>>;

const ACCESS_FLAGS = [
  { value: 0x80000000, name: 'GENERIC_READ' },
  { value: 0x40000000, name: 'GENERIC_WRITE' },
  { value: 0x20000000, name: 'GENERIC_EXECUTE' },
  { value: 0x10000000, name: 'GENERIC_ALL' },
];

const SHARE_FLAGS = [
  { value: 0x1, name: 'FILE_SHARE_READ' },
  { value: 0x2, name: 'FILE_SHARE_WRITE' },
  { value: 0x4, name: 'FILE_SHARE_DELETE' },
];

const CREATE_DISPOSITION = {
  1: 'CREATE_NEW',
  2: 'CREATE_ALWAYS',
  3: 'OPEN_EXISTING',
  4: 'OPEN_ALWAYS',
  5: 'TRUNCATE_EXISTING',
};

const FILE_ATTRIBUTES = [
  { value: 0x80, name: 'FILE_ATTRIBUTE_NORMAL' },
  { value: 0x2, name: 'FILE_ATTRIBUTE_HIDDEN' },
];

const ALLOCATION_FLAGS = [
  { value: 0x1000, name: 'MEM_COMMIT' },
  { value: 0x2000, name: 'MEM_RESERVE' },
];

const PROTECT_VALUES = {
  0x1: 'PAGE_NOACCESS',
  0x2: 'PAGE_READONLY',
  0x4: 'PAGE_READWRITE',
  0x10: 'PAGE_EXECUTE',
  0x20: 'PAGE_EXECUTE_READ',
  0x40: 'PAGE_EXECUTE_READWRITE',
};

const MESSAGE_BOX_FLAGS = [
  { value: 0x40, name: 'MB_ICONINFORMATION' },
  { value: 0x30, name: 'MB_ICONWARNING' },
  { value: 0x10, name: 'MB_ICONERROR' },
  { value: 0x4, name: 'MB_YESNO' },
  { value: 0x1, name: 'MB_OKCANCEL' },
];

const CONSTANT_ANNOTATIONS: ConstantAnnotationMap = {
  createfilew: {
    1: { flags: ACCESS_FLAGS },
    2: { flags: SHARE_FLAGS },
    4: { values: CREATE_DISPOSITION },
    5: { flags: FILE_ATTRIBUTES },
  },
  createfilea: {
    1: { flags: ACCESS_FLAGS },
    2: { flags: SHARE_FLAGS },
    4: { values: CREATE_DISPOSITION },
    5: { flags: FILE_ATTRIBUTES },
  },
  ntcreatefile: {
    1: { flags: ACCESS_FLAGS },
    6: { flags: SHARE_FLAGS },
    7: { values: CREATE_DISPOSITION },
  },
  virtualalloc: {
    2: { flags: ALLOCATION_FLAGS },
    3: { values: PROTECT_VALUES },
  },
  virtualprotect: {
    2: { values: PROTECT_VALUES },
  },
  ntallocatevirtualmemory: {
    4: { flags: ALLOCATION_FLAGS },
    5: { values: PROTECT_VALUES },
  },
  messageboxw: {
    3: { values: { 0: 'MB_OK' }, flags: MESSAGE_BOX_FLAGS },
  },
  messageboxa: {
    3: { values: { 0: 'MB_OK' }, flags: MESSAGE_BOX_FLAGS },
  },
};

function normalizeFunctionName(functionName: string): string {
  return functionName.split(/[!.]/).pop()?.replace(/^_+/, '').replace(/@\d+$/, '').toLowerCase() ?? functionName.toLowerCase();
}

function decomposeFlags(value: number, flags: Array<{ value: number; name: string }>): string | undefined {
  if (value === 0) return undefined;
  let remaining = value >>> 0;
  const parts: string[] = [];
  for (const flag of flags) {
    const flagValue = flag.value >>> 0;
    if (flagValue !== 0 && ((remaining & flagValue) >>> 0) === flagValue) {
      parts.push(flag.name);
      remaining = (remaining - flagValue) >>> 0;
    }
  }
  if (remaining !== 0) parts.push(`0x${remaining.toString(16).toUpperCase()}`);
  return parts.length > 0 ? parts.join(' | ') : undefined;
}

export function resolveConstantAnnotation(
  functionName: string,
  paramIndex: number,
  value: number,
): string | undefined {
  const spec = CONSTANT_ANNOTATIONS[normalizeFunctionName(functionName)]?.[paramIndex];
  if (!spec) return undefined;
  const unsigned = value >>> 0;
  const exact = spec.values?.[unsigned];
  if (exact) return exact;
  if (spec.flags) return decomposeFlags(unsigned, spec.flags);
  return undefined;
}

const PROTOTYPES_BY_NAME = new Map<string, ImportPrototype>(
  IMPORT_PROTOTYPES.map(proto => [proto.name.toLowerCase(), proto]),
);

export function resolveImportPrototype(name: string | undefined | null): ImportPrototype | undefined {
  if (!name) return undefined;
  const bare = name.split(/[!.]/).pop()?.replace(/^_+/, '').replace(/@\d+$/, '') ?? name;
  return PROTOTYPES_BY_NAME.get(bare.toLowerCase());
}

export function formatImportPrototype(proto: ImportPrototype): string {
  const args = proto.parameters.map(param => `${param.type} ${param.name}`).join(', ');
  return `${proto.returnType} ${proto.name}(${args})`;
}
