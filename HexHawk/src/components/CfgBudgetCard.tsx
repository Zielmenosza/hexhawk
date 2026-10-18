export type CfgBudgetCardProps = {
  nodes: number;
  edges: number;
  nodeBudget?: number;
  edgeBudget?: number;
  omittedNodes?: number;
  omittedEdges?: number;
  truncated?: boolean;
};

export function CfgBudgetCard({
  nodes,
  edges,
  nodeBudget,
  edgeBudget,
  omittedNodes = 0,
  omittedEdges = 0,
  truncated = false,
}: CfgBudgetCardProps) {
  const status = truncated ? 'truncated' : 'complete within budget';
  return (
    <section className="report-section cfg-budget-card" data-testid="cfg-budget-card">
      <div className="report-section-title">CFG budget proof</div>
      <div className="metadata-grid">
        <div className="metadata-row"><span>Status</span><span>{status}</span></div>
        <div className="metadata-row"><span>Rendered nodes</span><span>{nodes}</span></div>
        <div className="metadata-row"><span>Rendered edges</span><span>{edges}</span></div>
        <div className="metadata-row"><span>Node budget</span><span>{nodeBudget ?? 'not declared'}</span></div>
        <div className="metadata-row"><span>Edge budget</span><span>{edgeBudget ?? 'not declared'}</span></div>
      </div>
      {truncated ? (
        <p className="report-policy-note">
          CFG rendering was truncated for UI safety: {omittedNodes} omitted node(s), {omittedEdges} omitted edge(s).
        </p>
      ) : (
        <p className="report-policy-note">CFG rendering completed within the declared budget.</p>
      )}
    </section>
  );
}

export default CfgBudgetCard;
