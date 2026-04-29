/**
 * DomTreePanel.tsx — Dominator tree visualiser for a single function's CFG.
 *
 * Shows the forward dominator tree or post-dominator tree as a collapsible
 * list.  Clicking a node calls `onSelectBlock` so the CFG tab can highlight
 * the corresponding basic block.
 *
 * RE concepts exposed:
 *   - dominator / immediate dominator
 *   - post-dominator / immediate post-dominator
 *   - dominator tree
 *   - cross-reference view (dominance frontier per block)
 */

import React, { useState } from 'react';
import type { DomTree } from '../utils/ssaTransform';

// ─── Props ────────────────────────────────────────────────────────────────────

interface Props {
  /** Forward dominator tree (from buildSSAForm). */
  domTree: DomTree | null;
  /** Post-dominator tree (from computePostDominators), optional. */
  postDomTree?: DomTree | null;
  /** Called when the user clicks a block in the tree. */
  onSelectBlock?: (blockId: string) => void;
  /** Currently highlighted block ID (from CFG selection). */
  highlightedBlockId?: string | null;
}

// ─── Sub-component: a single tree node (recursive) ───────────────────────────

function DomNode({
  id,
  children,
  tree,
  depth,
  onSelectBlock,
  highlightedBlockId,
}: {
  id: string;
  children: string[];
  tree: DomTree;
  depth: number;
  onSelectBlock?: (blockId: string) => void;
  highlightedBlockId?: string | null;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const isHighlighted = id === highlightedBlockId;
  const df = tree.df.get(id);
  const idom = tree.idom.get(id);

  return (
    <div style={{ marginLeft: depth * 16 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.4rem',
          padding: '2px 4px',
          borderRadius: 3,
          cursor: 'pointer',
          background: isHighlighted ? 'rgba(0, 229, 204, 0.18)' : 'transparent',
          border: isHighlighted ? '1px solid #00e5cc' : '1px solid transparent',
          marginBottom: 1,
        }}
        title={idom ? `idom: ${idom}${df && df.size > 0 ? ' | DF: ' + Array.from(df).join(', ') : ''}` : 'entry'}
        onClick={() => onSelectBlock?.(id)}
      >
        {children.length > 0 && (
          <button
            type="button"
            style={{
              background: 'none',
              border: 'none',
              color: '#aaa',
              cursor: 'pointer',
              padding: 0,
              fontSize: '0.7rem',
              width: 14,
              flexShrink: 0,
            }}
            onClick={(e) => { e.stopPropagation(); setCollapsed(c => !c); }}
          >
            {collapsed ? '▶' : '▼'}
          </button>
        )}
        {children.length === 0 && <span style={{ width: 14, flexShrink: 0 }} />}
        <span style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: isHighlighted ? '#00e5cc' : '#ddd' }}>
          {id}
        </span>
        {df && df.size > 0 && (
          <span style={{ fontSize: '0.65rem', color: '#888', marginLeft: 'auto' }}>
            DF:{df.size}
          </span>
        )}
      </div>
      {!collapsed && children.length > 0 && (
        <div style={{ borderLeft: '1px solid #333', marginLeft: 7 }}>
          {children.map(child => (
            <DomNode
              key={child}
              id={child}
              children={tree.children.get(child) ?? []}
              tree={tree}
              depth={depth + 1}
              onSelectBlock={onSelectBlock}
              highlightedBlockId={highlightedBlockId}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function DomTreePanel({ domTree, postDomTree, onSelectBlock, highlightedBlockId }: Props) {
  const [showPost, setShowPost] = useState(false);

  const activeTree = showPost ? postDomTree : domTree;

  if (!domTree && !postDomTree) {
    return (
      <div className="panel" style={{ padding: '0.75rem' }}>
        <h4 style={{ margin: '0 0 0.5rem' }}>Dominator Tree</h4>
        <p style={{ color: '#888', fontSize: '0.8rem' }}>
          No dominator tree available. Decompile a function to compute SSA form.
        </p>
      </div>
    );
  }

  // Find the root(s): nodes whose idom is null
  const roots = activeTree
    ? Array.from(activeTree.idom.entries())
        .filter(([, parent]) => parent === null)
        .map(([id]) => id)
    : [];

  return (
    <div className="panel" style={{ padding: '0.75rem', overflow: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
        <h4 style={{ margin: 0, fontSize: '0.9rem' }}>
          {showPost ? 'Post-Dominator Tree' : 'Dominator Tree'}
        </h4>
        {postDomTree && (
          <button
            type="button"
            style={{
              fontSize: '0.72rem',
              padding: '0.1rem 0.5rem',
              background: 'rgba(56,139,253,0.12)',
              border: '1px solid rgba(56,139,253,0.3)',
              borderRadius: '0.35rem',
              color: '#79c0ff',
              cursor: 'pointer',
            }}
            onClick={() => setShowPost(p => !p)}
          >
            {showPost ? 'Show Forward Dom' : 'Show Post-Dom'}
          </button>
        )}
      </div>

      {!activeTree ? (
        <p style={{ color: '#888', fontSize: '0.8rem' }}>Tree not available.</p>
      ) : roots.length === 0 ? (
        <p style={{ color: '#888', fontSize: '0.8rem' }}>Empty tree.</p>
      ) : (
        <div>
          <div style={{ fontSize: '0.7rem', color: '#666', marginBottom: '0.4rem' }}>
            {activeTree.rpo.length} blocks · click to highlight in CFG · hover for idom + DF
          </div>
          {roots.map(root => (
            <DomNode
              key={root}
              id={root}
              children={activeTree.children.get(root) ?? []}
              tree={activeTree}
              depth={0}
              onSelectBlock={onSelectBlock}
              highlightedBlockId={highlightedBlockId}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default DomTreePanel;
