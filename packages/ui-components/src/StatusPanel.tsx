import React from 'react';

interface StatusPanelProps {
  status: string;
}

export function StatusPanel({ status }: StatusPanelProps) {
  return (
    <section className="status-panel">
      <strong>Status</strong>
      <p>{status}</p>
    </section>
  );
}
