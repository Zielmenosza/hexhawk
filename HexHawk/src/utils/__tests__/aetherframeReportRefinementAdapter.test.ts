import { describe, expect, it } from 'vitest';
import {
  AETHERFRAME_REPORT_LINEAGE_HEADING,
  describeHexHawkReportRefinement,
  makeHexHawkReportLineageSidecar,
  refineHexHawkReportMarkdown,
} from '../aetherframeReportRefinementAdapter';

const baseMarkdown = [
  '# HexHawk Intelligence Report',
  '',
  '## Verdict',
  '',
  '| Field | Value |',
  '|-------|-------|',
  '| Classification | **SUSPICIOUS** |',
  '| Threat Score | 66/100 |',
  '| Confidence | 83% (high) |',
].join('\n');

const verdict = {
  classification: 'suspicious',
  threatScore: 66,
  confidence: 83,
  sourceEngine: 'gyre',
};

describe('aetherframe report refinement adapter', () => {
  it('appends visible bounded lineage without changing the source report body', () => {
    const result = refineHexHawkReportMarkdown({
      markdown: baseMarkdown,
      verdict,
      policy: { enabled: true, reason: 'unit-test' },
    });

    expect(result.markdown).toContain(baseMarkdown);
    expect(result.markdown).toContain(AETHERFRAME_REPORT_LINEAGE_HEADING);
    expect(result.markdown).toContain('| Adapter | hexhawk.report.markdown |');
    expect(result.markdown).toContain('| Protected classification | suspicious |');
    expect(result.markdown).toContain('| Protected threat score | 66 |');
    expect(result.markdown).toContain('| Protected confidence | 83% |');
    expect(result.markdown).toContain('| Protected source engine | gyre |');
    expect(result.markdown).toContain('GYRE remains the sole verdict authority');
    expect(result.lineage.blockedMutations).toEqual(expect.arrayContaining([
      'classification',
      'threatScore',
      'confidence',
      'source_engine',
      'gyre_is_sole_verdict_source',
      'malware_family',
      'verdictTruth',
      'nestEvidenceSelection',
    ]));
    expect(result.lineage.coreFrameId).toBe('adapter.hexhawk.verdict-lineage.v1');
    expect(result.lineage.coreAdapterContractValid).toBe(true);
    expect(result.lineage.coreSchemaVersion).toBe('aetherframe.frame.v1');
  });

  it('is idempotent and does not duplicate the lineage section', () => {
    const first = refineHexHawkReportMarkdown({ markdown: baseMarkdown, verdict });
    const second = refineHexHawkReportMarkdown({ markdown: first.markdown, verdict });

    const occurrences = second.markdown.split(AETHERFRAME_REPORT_LINEAGE_HEADING).length - 1;
    expect(occurrences).toBe(1);
  });

  it('returns unchanged markdown with disabled lineage when policy disables AETHERFRAME', () => {
    const result = refineHexHawkReportMarkdown({
      markdown: baseMarkdown,
      verdict,
      policy: { enabled: false, reason: 'high-assurance-mode' },
    });

    expect(result.markdown).toBe(baseMarkdown);
    expect(result.lineage.applied).toBe(false);
    expect(result.lineage.passId).toBe('aetherframe-disabled');
    expect(result.lineage.mutationScope).toBe('none');
    expect(result.lineage.policyReason).toBe('high-assurance-mode');
  });

  it('describes enabled and disabled lineage for JSON/export metadata without rewriting markdown', () => {
    const enabled = describeHexHawkReportRefinement({ enabled: true, reason: 'json-export' });
    expect(enabled.applied).toBe(true);
    expect(enabled.passId).toBe('hexhawk-report-authority-lineage-package');
    expect(enabled.mutationScope).toBe('package');
    expect(enabled.blockedMutations).toEqual(expect.arrayContaining(['classification', 'nestEvidenceSelection']));

    const disabled = describeHexHawkReportRefinement({ enabled: false, reason: 'high-assurance-json' });
    expect(disabled.applied).toBe(false);
    expect(disabled.passId).toBe('aetherframe-disabled');
    expect(disabled.mutationScope).toBe('none');
    expect(disabled.policyReason).toBe('high-assurance-json');
  });

  it('creates a JSON lineage sidecar that proves verdict fields are copied and not recomputed', () => {
    const sidecar = makeHexHawkReportLineageSidecar({
      reportId: 'report-fixture-001',
      verdict,
      policy: { enabled: true, reason: 'json-sidecar-test' },
    });

    expect(sidecar.schemaVersion).toBe('hexhawk.aetherframe_report_lineage_sidecar.v1');
    expect(sidecar.reportId).toBe('report-fixture-001');
    expect(sidecar.verdictCopy).toEqual(verdict);
    expect(sidecar.preservedVerdictFields).toMatchObject({
      classification: { source: 'copied_from_gyre_report_export', value: 'suspicious', recomputedByAetherFrame: false },
      threatScore: { source: 'copied_from_gyre_report_export', value: 66, recomputedByAetherFrame: false },
      confidence: { source: 'copied_from_gyre_report_export', value: 83, recomputedByAetherFrame: false },
      sourceEngine: { source: 'copied_from_gyre_report_export', value: 'gyre', recomputedByAetherFrame: false },
    });
    expect(sidecar.verdictIntegrity.gyreRemainsSoleVerdictSource).toBe(true);
    expect(sidecar.verdictIntegrity.aetherframeRecomputedVerdict).toBe(false);
    expect(sidecar.verdictIntegrity.bodyMutationAllowed).toBe(false);
    expect(sidecar.proofLimits.join(' ')).toContain('does not prove GYRE correctness');
  });
});
