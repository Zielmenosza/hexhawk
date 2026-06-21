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
