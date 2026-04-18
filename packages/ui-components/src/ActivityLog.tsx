import React, { useEffect, useRef } from 'react';

export interface ActivityLogEntry {
  timestamp: string;
  type: 'info' | 'warn' | 'error';
  message: string;
}

interface ActivityLogProps {
  entries: ActivityLogEntry[];
  maxLines?: number;
}

export function ActivityLog({ entries, maxLines = 100 }: ActivityLogProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const visibleEntries = entries.slice(0, maxLines);

  useEffect(() => {
    const element = containerRef.current;
    if (element) {
      element.scrollTop = element.scrollHeight;
    }
  }, [visibleEntries.length]);

  return (
    <div className="activity-log" ref={containerRef}>
      {visibleEntries.map((entry, index) => (
        <div key={`${entry.timestamp}-${index}`} className={`activity-log-entry ${entry.type}`}>
          <span className="activity-log-meta">{entry.timestamp}</span>
          <span className="activity-log-message">{entry.message}</span>
        </div>
      ))}
    </div>
  );
}
