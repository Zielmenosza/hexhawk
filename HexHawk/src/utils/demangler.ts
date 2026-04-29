/**
 * demangler.ts — C++ Itanium ABI / MSVC name demangler
 *
 * Handles the most common mangling forms encountered in RE:
 *   Itanium (_Z prefix) — used by GCC, Clang, ELF/Mach-O
 *   MSVC   (?  prefix) — used by MSVC PE/COFF
 *
 * This is a best-effort heuristic demangler — it correctly handles the vast
 * majority of real-world mangled names without pulling in a native library.
 */

// ─── Itanium ABI — types ──────────────────────────────────────────────────────

interface ParseResult<T> {
  value: T;
  rest: string;
}

// ─── Itanium ABI — built-in type codes ───────────────────────────────────────

const BUILTIN_TYPES: Record<string, string> = {
  v: 'void', b: 'bool', c: 'char', a: 'signed char', h: 'unsigned char',
  s: 'short', t: 'unsigned short', i: 'int', j: 'unsigned int',
  l: 'long', m: 'unsigned long', x: 'long long', y: 'unsigned long long',
  n: '__int128', o: 'unsigned __int128', f: 'float', d: 'double',
  e: 'long double', g: '__float128', z: '...', u: 'char8_t',
  Du: 'char8_t', Ds: 'char16_t', Di: 'char32_t', Dn: 'decltype(nullptr)',
};

// ─── Itanium ABI — operator codes ────────────────────────────────────────────

const OPERATORS: Record<string, string> = {
  nw: 'operator new', na: 'operator new[]',
  dl: 'operator delete', da: 'operator delete[]',
  ps: 'operator+', ng: 'operator-',
  ad: 'operator&', de: 'operator*',
  co: 'operator~', pl: 'operator+', mi: 'operator-',
  ml: 'operator*', dv: 'operator/', rm: 'operator%',
  an: 'operator&', or: 'operator|', eo: 'operator^',
  aS: 'operator=', pL: 'operator+=', mI: 'operator-=',
  mL: 'operator*=', dV: 'operator/=', rM: 'operator%=',
  aN: 'operator&=', oR: 'operator|=', eO: 'operator^=',
  ls: 'operator<<', rs: 'operator>>', lS: 'operator<<=', rS: 'operator>>=',
  eq: 'operator==', ne: 'operator!=', lt: 'operator<',
  gt: 'operator>', le: 'operator<=', ge: 'operator>=',
  ss: 'operator<=>',
  nt: 'operator!', aa: 'operator&&', oo: 'operator||',
  pp: 'operator++', mm: 'operator--', cm: 'operator,',
  pm: 'operator->*', pt: 'operator->',
  cl: 'operator()', ix: 'operator[]',
  qu: 'operator?', cv: 'operator',
  li: 'operator""',
};

// ─── Itanium ABI — parser state ───────────────────────────────────────────────

interface ParseState {
  substitutions: string[];  // previous types for S_ back-references
  templateArgs: string[];   // current template arg list
}

function newState(): ParseState {
  return { substitutions: [], templateArgs: [] };
}

// ─── Itanium ABI — parse a source name (length-prefixed) ─────────────────────

function parseSourceName(s: string): ParseResult<string> | null {
  const m = s.match(/^(\d+)/);
  if (!m) return null;
  const len = parseInt(m[1], 10);
  const rest = s.slice(m[1].length);
  if (rest.length < len) return null;
  return { value: rest.slice(0, len), rest: rest.slice(len) };
}

// ─── Itanium ABI — parse a qualified name ────────────────────────────────────

function parseNestedName(s: string, state: ParseState): ParseResult<string> | null {
  // N [CV-qualifiers] name+ E
  if (!s.startsWith('N')) return null;
  s = s.slice(1);

  // Consume optional CV-qualifiers: K (const), V (volatile), r (restrict)
  let cvPrefix = '';
  while (s.startsWith('K') || s.startsWith('V') || s.startsWith('r')) {
    if (s.startsWith('K')) cvPrefix += 'const ';
    if (s.startsWith('V')) cvPrefix += 'volatile ';
    s = s.slice(1);
  }

  const parts: string[] = [];
  while (s.length > 0 && !s.startsWith('E')) {
    const part = parseName(s, state);
    if (!part) break;
    parts.push(part.value);
    s = part.rest;
    state.substitutions.push(parts.join('::'));
  }
  if (!s.startsWith('E')) return null;
  s = s.slice(1);

  return { value: cvPrefix + parts.join('::'), rest: s };
}

// ─── Itanium ABI — parse a type ──────────────────────────────────────────────

function parseType(s: string, state: ParseState): ParseResult<string> | null {
  if (s.length === 0) return null;

  // Pointer
  if (s.startsWith('P')) {
    const inner = parseType(s.slice(1), state);
    if (!inner) return null;
    return { value: inner.value + '*', rest: inner.rest };
  }

  // Reference
  if (s.startsWith('R')) {
    const inner = parseType(s.slice(1), state);
    if (!inner) return null;
    return { value: inner.value + '&', rest: inner.rest };
  }

  // R-value reference (C++11)
  if (s.startsWith('O')) {
    const inner = parseType(s.slice(1), state);
    if (!inner) return null;
    return { value: inner.value + '&&', rest: inner.rest };
  }

  // Const
  if (s.startsWith('K')) {
    const inner = parseType(s.slice(1), state);
    if (!inner) return null;
    return { value: 'const ' + inner.value, rest: inner.rest };
  }

  // Volatile
  if (s.startsWith('V')) {
    const inner = parseType(s.slice(1), state);
    if (!inner) return null;
    return { value: 'volatile ' + inner.value, rest: inner.rest };
  }

  // Substitution S_/S0_/Sn_
  if (s.startsWith('S')) {
    const sub = parseSubstitution(s, state);
    if (sub) return sub;
  }

  // Template instantiation (back-ref T_/T0_/Tn_)
  if (s.startsWith('T')) {
    const tr = parseTemplateArg(s, state);
    if (tr) return tr;
  }

  // Builtin: Du/Ds/Di/Dn (2-char builtins first)
  for (const [code, name] of Object.entries(BUILTIN_TYPES)) {
    if (code.length === 2 && s.startsWith(code)) {
      return { value: name, rest: s.slice(code.length) };
    }
  }
  const oneChar = BUILTIN_TYPES[s[0]];
  if (oneChar) return { value: oneChar, rest: s.slice(1) };

  // Function type F ... E
  if (s.startsWith('F')) {
    const fRet = parseFunctionType(s, state);
    if (fRet) return fRet;
  }

  // Nested name
  if (s.startsWith('N')) {
    const nested = parseNestedName(s, state);
    if (nested) {
      state.substitutions.push(nested.value);
      return nested;
    }
  }

  // Template-id I...E
  if (s.startsWith('I')) {
    return null; // handled in parseName context
  }

  // Source name (digit-prefixed)
  const src = parseSourceName(s);
  if (src) {
    state.substitutions.push(src.value);
    return src;
  }

  return null;
}

// ─── Itanium ABI — substitutions ─────────────────────────────────────────────

const STANDARD_SUBS: Record<string, string> = {
  'Ss': 'std::string',
  'Sa': 'std::allocator',
  'Sb': 'std::basic_string',
  'Si': 'std::basic_istream<char>',
  'So': 'std::basic_ostream<char>',
  'Sd': 'std::basic_iostream<char>',
  'St': 'std',
};

function parseSubstitution(s: string, state: ParseState): ParseResult<string> | null {
  // Standard abbreviations St/Sa/Sb/Si/So/Sd/Ss
  for (const [code, name] of Object.entries(STANDARD_SUBS)) {
    if (s.startsWith(code)) {
      return { value: name, rest: s.slice(code.length) };
    }
  }

  // S_ (most recent), S0_ (second), S1_, ... Sn_
  const subMatch = s.match(/^S([0-9A-Z]?)_/);
  if (subMatch) {
    const rest = s.slice(subMatch[0].length);
    const idx = subMatch[1] === '' ? state.substitutions.length - 1
      : parseInt(subMatch[1], 36);  // A=10, B=11, etc.
    const name = state.substitutions[idx] ?? `S${subMatch[1]}_`;
    return { value: name, rest };
  }

  return null;
}

// ─── Itanium ABI — template args ─────────────────────────────────────────────

function parseTemplateArgs(s: string, state: ParseState): ParseResult<string> | null {
  if (!s.startsWith('I')) return null;
  s = s.slice(1);
  const args: string[] = [];
  while (s.length > 0 && !s.startsWith('E')) {
    // Literal int: Li123E
    if (s.startsWith('L')) {
      const litMatch = s.match(/^L[a-z](\d+)E/);
      if (litMatch) {
        args.push(litMatch[1]);
        s = s.slice(litMatch[0].length);
        continue;
      }
    }
    const t = parseType(s, state);
    if (!t) { s = s.slice(1); continue; }
    args.push(t.value);
    state.templateArgs.push(t.value);
    s = t.rest;
  }
  if (!s.startsWith('E')) return null;
  return { value: `<${args.join(', ')}>`, rest: s.slice(1) };
}

function parseTemplateArg(s: string, state: ParseState): ParseResult<string> | null {
  const match = s.match(/^T([0-9A-Z]?)_/);
  if (!match) return null;
  const rest = s.slice(match[0].length);
  const idx = match[1] === '' ? 0 : parseInt(match[1], 36) + 1;
  const name = state.templateArgs[idx] ?? `T${match[1]}_`;
  return { value: name, rest };
}

// ─── Itanium ABI — function type ─────────────────────────────────────────────

function parseFunctionType(s: string, state: ParseState): ParseResult<string> | null {
  if (!s.startsWith('F')) return null;
  s = s.slice(1);
  if (s.startsWith('Y')) s = s.slice(1); // extern "C"

  const retType = parseType(s, state);
  if (!retType) return null;
  s = retType.rest;

  const params: string[] = [];
  while (s.length > 0 && !s.startsWith('E')) {
    const p = parseType(s, state);
    if (!p) { s = s.slice(1); continue; }
    params.push(p.value);
    s = p.rest;
  }
  if (s.startsWith('E')) s = s.slice(1);

  const paramStr = params.length === 0 ? 'void'
    : params.length === 1 && params[0] === 'void' ? 'void'
    : params.join(', ');
  return { value: `${retType.value}(${paramStr})`, rest: s };
}

// ─── Itanium ABI — parse a name token ────────────────────────────────────────

function parseName(s: string, state: ParseState): ParseResult<string> | null {
  // Nested
  if (s.startsWith('N')) return parseNestedName(s, state);

  // Substitution
  if (s.startsWith('S')) {
    const sub = parseSubstitution(s, state);
    if (sub) return sub;
  }

  // Operators
  for (const [code, name] of Object.entries(OPERATORS)) {
    if (s.startsWith(code)) {
      return { value: name, rest: s.slice(code.length) };
    }
  }

  // Destructor D1/D0/D2
  if (s.startsWith('D1') || s.startsWith('D0') || s.startsWith('D2')) {
    const src = parseSourceName(s.slice(2));
    if (src) return { value: `~${src.value}`, rest: src.rest };
  }

  // Constructor C1/C2/C3
  if (s.startsWith('C1') || s.startsWith('C2') || s.startsWith('C3')) {
    const src = parseSourceName(s.slice(2));
    if (src) return src;
  }

  // Source name (digit-prefixed)
  const src = parseSourceName(s);
  if (!src) return null;

  let result = src.value;
  let rest = src.rest;
  state.substitutions.push(result);

  // Template args I...E
  if (rest.startsWith('I')) {
    const targs = parseTemplateArgs(rest, state);
    if (targs) {
      result += targs.value;
      rest = targs.rest;
      state.substitutions.push(result);
    }
  }

  return { value: result, rest };
}

// ─── Itanium ABI — parse function params ─────────────────────────────────────

function parseParams(s: string, state: ParseState): string[] {
  const params: string[] = [];
  while (s.length > 0) {
    const t = parseType(s, state);
    if (!t) break;
    if (t.value !== 'void' || params.length > 0) {
      params.push(t.value);
    }
    s = t.rest;
  }
  return params;
}

// ─── Itanium ABI — top-level demangler ───────────────────────────────────────

function demangleItanium(mangled: string): string | null {
  if (!mangled.startsWith('_Z')) return null;
  let s = mangled.slice(2);

  const state = newState();

  // Nested name N...E
  if (s.startsWith('N')) {
    const nested = parseNestedName(s, state);
    if (!nested) return null;
    const params = parseParams(nested.rest, state);
    const paramStr = params.length === 0 ? 'void' : params.join(', ');
    return `${nested.value}(${paramStr})`;
  }

  // Global name: operator or source name
  const nameResult = parseName(s, state);
  if (!nameResult) return null;

  const funcName = nameResult.value;
  const params = parseParams(nameResult.rest, state);
  const paramStr = params.length === 0 ? 'void' : params.join(', ');
  return `${funcName}(${paramStr})`;
}

// ─── MSVC mangling — basic demangler ─────────────────────────────────────────

const MSVC_CALL_CONV: Record<string, string> = {
  'A': '__cdecl', 'C': '__pascal', 'E': '__thiscall', 'G': '__stdcall',
  'I': '__fastcall', 'K': '', 'M': '__clrcall', 'O': '__eabi',
  'Q': '__vectorcall', 'S': '__swift_1', 'U': '__swift_2', 'W': '__swift_3',
};

const MSVC_BUILTINS: Record<string, string> = {
  'X': 'void', 'D': 'char', 'C': 'signed char', 'E': 'unsigned char',
  'F': 'short', 'G': 'unsigned short', 'H': 'int', 'I': 'unsigned int',
  'J': 'long', 'K': 'unsigned long', '_J': '__int64', '_K': 'unsigned __int64',
  'M': 'float', 'N': 'double', 'O': 'long double', 'Z': '...',
};

function demangleMSVC(mangled: string): string | null {
  if (!mangled.startsWith('?')) return null;
  // Strip leading ?
  let s = mangled.slice(1);

  // Parse function name (up to first @)
  const nameEnd = s.indexOf('@');
  if (nameEnd < 0) return null;
  let funcName = s.slice(0, nameEnd);

  // Handle special operators (?0 constructor, ?1 destructor, etc.)
  const OP_MAP: Record<string, string> = {
    '0': 'ctor', '1': '~dtor', '2': 'operator new', '3': 'operator delete',
    '4': 'operator=', '5': 'operator>>', '6': 'operator<<', '7': 'operator!',
    '8': 'operator==', '9': 'operator!=', 'A': 'operator[]', 'B': 'operator ',
    'C': 'operator->', 'D': 'operator*', 'E': 'operator++', 'F': 'operator--',
    'G': 'operator-', 'H': 'operator+', 'I': 'operator&', 'J': 'operator->*',
    'K': 'operator/', 'L': 'operator%', 'M': 'operator<', 'N': 'operator<=',
    'O': 'operator>', 'P': 'operator>=', 'Q': 'operator,', 'R': 'operator()',
    'S': 'operator~', 'T': 'operator^', 'U': 'operator|', 'V': 'operator&&',
    'W': 'operator||', 'X': 'operator*=', 'Y': 'operator+=', 'Z': 'operator-=',
  };
  if (funcName.startsWith('?')) {
    funcName = OP_MAP[funcName[1]] ?? funcName;
  }

  s = s.slice(nameEnd + 1);

  // Parse nested scope (class names separated by @, ended by @)
  const scopeParts: string[] = [funcName];
  while (s.length > 0 && s[0] !== '@') {
    const partEnd = s.indexOf('@');
    if (partEnd < 0) break;
    scopeParts.unshift(s.slice(0, partEnd));
    s = s.slice(partEnd + 1);
  }
  if (s.startsWith('@')) s = s.slice(1);

  const fullName = scopeParts.join('::');

  // Parse access/function modifiers (skip for display)
  if (s.length < 2) return fullName + '()';
  // s[0] = protection level Q(public),I(protected),A(private), etc.
  // s[1] = function type: A=normal,C=const,E=volatile,G=const volatile
  const isConst = (s[1] === 'C' || s[1] === 'G') ? ' const' : '';
  s = s.slice(2);

  // Parse calling convention
  const callConv = MSVC_CALL_CONV[s[0]] ?? '';
  s = s.slice(1);

  // Return type
  const retType = MSVC_BUILTINS[s[0]] ?? s[0];
  s = s.slice(1);

  // Parameters (best-effort: parse builtin types until Z or end)
  const params: string[] = [];
  while (s.length > 0 && s[0] !== 'Z' && s[0] !== '@') {
    const t = MSVC_BUILTINS[s[0]];
    if (t) {
      if (t !== 'void' || params.length > 0) params.push(t);
      s = s.slice(1);
    } else if (s[0] === 'P') {
      // Pointer
      s = s.slice(1);
      const inner = MSVC_BUILTINS[s[0]] ?? s[0];
      params.push(inner + '*');
      s = s.slice(1);
    } else {
      s = s.slice(1);
    }
  }

  const paramStr = params.length === 0 ? 'void' : params.join(', ');
  const conv = callConv ? `${callConv} ` : '';
  return `${retType} ${conv}${fullName}(${paramStr})${isConst}`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Attempt to demangle a C++ symbol name.
 * Returns the original name if it cannot be demangled (not mangled, or unsupported format).
 *
 * Supports:
 *   - Itanium ABI (_Z prefix, GCC/Clang)
 *   - MSVC (? prefix, MSVC/Windows)
 */
export function demangle(name: string): string {
  try {
    if (name.startsWith('_Z')) {
      return demangleItanium(name) ?? name;
    }
    if (name.startsWith('?')) {
      return demangleMSVC(name) ?? name;
    }
  } catch {
    // Malformed mangled name — return raw
  }
  return name;
}

/**
 * Returns true if the symbol name appears to be C++ mangled.
 */
export function isMangled(name: string): boolean {
  return name.startsWith('_Z') || name.startsWith('?');
}

/**
 * Demangle a list of symbol names, returning only those that changed.
 */
export function demangleAll(names: string[]): Array<{ raw: string; demangled: string }> {
  return names
    .map(n => ({ raw: n, demangled: demangle(n) }))
    .filter(r => r.raw !== r.demangled);
}
