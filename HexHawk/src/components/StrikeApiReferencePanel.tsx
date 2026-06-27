import React, { useMemo, useState } from 'react';
import { STRIKE_API_METHODS } from '../utils/strikeApiReference';

export default function StrikeApiReferencePanel() {
  const [query, setQuery] = useState('');
  const methods = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return STRIKE_API_METHODS;
    return STRIKE_API_METHODS.filter(method =>
      `${method.name} ${method.signature} ${method.description} ${method.example}`.toLowerCase().includes(needle),
    );
  }, [query]);

  return (
    <div className="panel" data-testid="panel-strike-api">
      <h3>STRIKE API Reference</h3>
      <p style={{ color: '#aaa', maxWidth: '60rem' }}>
        Searchable scripting surface for advisory STRIKE helpers. These methods produce evidence and workflow support; GYRE remains the sole verdict authority.
      </p>
      <input
        aria-label="Search STRIKE API methods"
        className="search-input"
        data-testid="strike-api-search"
        placeholder="Search methods, signatures, examples..."
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        style={{ width: '100%', margin: '0.75rem 0 1rem' }}
      />
      <div className="imports-table" role="list" aria-label="STRIKE API methods">
        {methods.map(method => (
          <div key={method.name} className="imports-row" role="listitem" style={{ gridTemplateColumns: '1fr', alignItems: 'stretch' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <strong>{method.name}</strong>
                <span className="import-threat-badge">{method.advisory ? 'advisory evidence' : 'pipeline'}</span>
                <span className="import-threat-badge">{method.verdictPipeline ? 'verdict pipeline' : 'not verdict authority'}</span>
              </div>
              <code style={{ display: 'block', marginTop: '0.35rem', whiteSpace: 'pre-wrap' }}>{method.signature}</code>
              <p style={{ margin: '0.45rem 0', color: '#bbb' }}>{method.description}</p>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}><code>{method.example}</code></pre>
            </div>
          </div>
        ))}
      </div>
      {methods.length === 0 && <div className="empty-state">No STRIKE methods match that search.</div>}
    </div>
  );
}
