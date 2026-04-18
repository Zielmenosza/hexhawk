/**
 * Annotation System — Unified user notes attached to addresses, blocks, and strings.
 *
 * Annotations are stored in localStorage under 'hexhawk.annotations' and
 * indexed by a string key of the form "addr:<hex>" for addresses,
 * "block:<id>" for CFG blocks, or "str:<offset>" for string offsets.
 */

export type AnnotationKind = 'user' | 'auto-xref' | 'auto-pattern';

export interface Annotation {
  id: string;
  key: string;         // e.g. "addr:0x004011a0"
  address?: number;    // numeric address for quick lookup
  kind: AnnotationKind;
  text: string;
  timestamp: number;
}

const STORAGE_KEY = 'hexhawk.annotations';

// ─── Key helpers ─────────────────────────────────────────────────────────────

export function addrKey(address: number): string {
  return `addr:0x${address.toString(16).toUpperCase()}`;
}

export function blockKey(blockId: string): string {
  return `block:${blockId}`;
}

export function strKey(offset: number): string {
  return `str:${offset}`;
}

// ─── Storage ──────────────────────────────────────────────────────────────────

export function loadAnnotations(): Map<string, Annotation[]> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return new Map();
    const obj = JSON.parse(raw) as Record<string, Annotation[]>;
    return new Map(Object.entries(obj));
  } catch {
    return new Map();
  }
}

export function saveAnnotations(annotations: Map<string, Annotation[]>): void {
  try {
    const obj: Record<string, Annotation[]> = {};
    for (const [k, v] of annotations) {
      obj[k] = v;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(obj));
  } catch {
    // Silently fail on storage quota errors
  }
}

// ─── CRUD helpers ─────────────────────────────────────────────────────────────

export function addAnnotation(
  annotations: Map<string, Annotation[]>,
  key: string,
  text: string,
  kind: AnnotationKind = 'user',
  address?: number,
): Map<string, Annotation[]> {
  const next = new Map(annotations);
  const existing = next.get(key) ?? [];
  const newAnnotation: Annotation = {
    id: `ann_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    key,
    address,
    kind,
    text: text.trim(),
    timestamp: Date.now(),
  };
  next.set(key, [...existing, newAnnotation]);
  saveAnnotations(next);
  return next;
}

export function updateAnnotation(
  annotations: Map<string, Annotation[]>,
  key: string,
  id: string,
  text: string,
): Map<string, Annotation[]> {
  const next = new Map(annotations);
  const existing = next.get(key) ?? [];
  next.set(key, existing.map(a => a.id === id ? { ...a, text: text.trim(), timestamp: Date.now() } : a));
  saveAnnotations(next);
  return next;
}

export function deleteAnnotation(
  annotations: Map<string, Annotation[]>,
  key: string,
  id: string,
): Map<string, Annotation[]> {
  const next = new Map(annotations);
  const existing = next.get(key) ?? [];
  const updated = existing.filter(a => a.id !== id);
  if (updated.length === 0) {
    next.delete(key);
  } else {
    next.set(key, updated);
  }
  saveAnnotations(next);
  return next;
}

export function getAnnotations(
  annotations: Map<string, Annotation[]>,
  key: string,
): Annotation[] {
  return annotations.get(key) ?? [];
}

// ─── Auto-annotation helpers ──────────────────────────────────────────────────

/** Generate automatic cross-reference annotations from reference maps */
export function buildAutoXrefAnnotations(
  instructions: Array<{ address: number; mnemonic: string; operands: string }>,
  referencesMap: Map<number, Set<number>>,
): Map<string, Annotation[]> {
  const result = new Map<string, Annotation[]>();

  for (const [target, sources] of referencesMap) {
    if (sources.size === 0) continue;
    const key = addrKey(target);
    const text = `Referenced by ${sources.size} instruction(s): ${
      Array.from(sources).slice(0, 3).map(a => '0x' + a.toString(16).toUpperCase()).join(', ')
    }${sources.size > 3 ? '…' : ''}`;
    result.set(key, [{
      id: `auto_xref_${target}`,
      key,
      address: target,
      kind: 'auto-xref',
      text,
      timestamp: 0,
    }]);
  }

  return result;
}
