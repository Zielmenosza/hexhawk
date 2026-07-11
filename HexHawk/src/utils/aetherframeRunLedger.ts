export type AetherframeRunLedgerInput = {
  repo: string;
  agentReport: string;
  allowedPaths?: string[];
  forbiddenPaths?: string[];
  gitStatusShort?: string;
  currentBranch?: string;
};

export type AetherframeRunLedgerJson = {
  repo: string;
  current_branch: string;
  git_status_short: string;
  changed_files: string[];
  staged_files: string[];
  forbidden_path_hits: string[];
  claimed_tests: string[];
  claimed_commits: string[];
  detected_human_approval_requests: string[];
  commit_ready: boolean;
  reasons_not_ready: string[];
  advisory_notes: string[];
};

const DEFAULT_FORBIDDEN_PATHS = [
  '.env',
  '.pem',
  '.pfx',
  '.key',
  'AppData/',
  'credentials',
  'dist/',
  'installer',
  'node_modules/',
  'package-lock.json',
  'pycache/',
  'screenshots/',
  'secret',
  'site-build/',
  'target/',
  'tokens',
  'work/',
  '.zip',
];

const TEST_COMMAND_PATTERN = /\b(cargo\s+test|yarn\s+(?:workspace\s+\S+\s+)?test|npm\s+test|pnpm\s+test|vitest(?:\s+run)?|pytest|cargo\s+clippy|tsc\s+--noEmit)\b/i;
const TEST_PASS_CLAIM_PATTERN = /\b(test(?:s|ed|ing)?|validation|suite|check(?:s)?)\b.*\b(pass(?:ed|es)?|green|ok|success(?:ful)?)\b|\b(pass(?:ed|es)?|green|ok|success(?:ful)?)\b.*\b(test(?:s|ed|ing)?|validation|suite|check(?:s)?)\b/i;
const COMMIT_PATTERN = /\b(?:commit(?:ted)?|commit hash|sha)\b[^\n]*(?:[0-9a-f]{7,40}|\[[A-Z][^\]]*\])/i;
const HUMAN_APPROVAL_PATTERN = /\b(?:approval|approve|human review|operator review|manual review|wait for approval|stop for approval)\b/i;
const AUTHORITY_TOUCH_PATTERN = /\b(?:GYRE|verdict|classification|sole verdict|threat score|source engine)\b/i;

function normalizePath(path: string): string {
  return path.trim().replace(/\\+/g, '/').replace(/^\.\//, '');
}

function stripRenamePath(path: string): string {
  const normalized = normalizePath(path);
  const arrow = normalized.split(/\s+->\s+/);
  return arrow[arrow.length - 1].replace(/[{}]/g, '');
}

export function parseGitStatusShort(statusShort: string): { changedFiles: string[]; stagedFiles: string[] } {
  const changedFiles: string[] = [];
  const stagedFiles: string[] = [];

  for (const rawLine of statusShort.split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.startsWith('##')) continue;
    const status = rawLine.slice(0, 2);
    const pathPart = rawLine.length > 3 ? rawLine.slice(3) : rawLine.slice(2).trimStart();
    const filePath = stripRenamePath(pathPart);
    if (!filePath) continue;

    changedFiles.push(filePath);
    if (status[0] !== ' ' && status[0] !== '?') {
      stagedFiles.push(filePath);
    }
  }

  return {
    changedFiles: Array.from(new Set(changedFiles)),
    stagedFiles: Array.from(new Set(stagedFiles)),
  };
}

function pathMatchesRule(path: string, rule: string): boolean {
  const normalizedPath = normalizePath(path).toLowerCase();
  const normalizedRule = normalizePath(rule).toLowerCase();
  if (!normalizedRule) return false;
  if (normalizedRule.endsWith('/')) {
    return normalizedPath === normalizedRule.slice(0, -1) || normalizedPath.startsWith(normalizedRule);
  }
  return normalizedPath === normalizedRule || normalizedPath.startsWith(`${normalizedRule}/`) || normalizedPath.includes(normalizedRule);
}

function isAllowed(path: string, allowedPaths: string[]): boolean {
  if (allowedPaths.length === 0) return true;
  return allowedPaths.some(rule => pathMatchesRule(path, rule));
}

function linesMatching(report: string, pattern: RegExp): string[] {
  return report
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line.length > 0 && pattern.test(line));
}

export function buildAetherframeRunLedger(input: AetherframeRunLedgerInput): AetherframeRunLedgerJson {
  const gitStatusShort = input.gitStatusShort ?? '';
  const currentBranch = input.currentBranch ?? 'unknown';
  const { changedFiles, stagedFiles } = parseGitStatusShort(gitStatusShort);
  const forbiddenRules = [...DEFAULT_FORBIDDEN_PATHS, ...(input.forbiddenPaths ?? [])];
  const allowedRules = input.allowedPaths ?? [];

  const forbiddenPathHits = changedFiles.filter(path => forbiddenRules.some(rule => pathMatchesRule(path, rule)));
  const disallowedPathHits = changedFiles.filter(path => !isAllowed(path, allowedRules));
  const reportLines = input.agentReport.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const claimedTests = reportLines.filter(line => TEST_COMMAND_PATTERN.test(line) || TEST_PASS_CLAIM_PATTERN.test(line));
  const commandEvidence = reportLines.filter(line => TEST_COMMAND_PATTERN.test(line));
  const passClaims = reportLines.filter(line => TEST_PASS_CLAIM_PATTERN.test(line));
  const claimedCommits = linesMatching(input.agentReport, COMMIT_PATTERN);
  const explicitApprovalRequests = linesMatching(input.agentReport, HUMAN_APPROVAL_PATTERN);
  const authorityTouches = reportLines.filter(line => AUTHORITY_TOUCH_PATTERN.test(line));
  const detectedHumanApprovalRequests = [
    ...explicitApprovalRequests,
    ...authorityTouches.map(line => `authority-boundary review required: ${line}`),
  ];

  const reasonsNotReady: string[] = [];
  const advisoryNotes: string[] = [
    'AetherFrame run-ledger is read-only advisory support; it does not stage, commit, classify, or approve changes.',
    'Commit readiness is a custody gate, not an authority verdict or confidence score.',
  ];

  if (changedFiles.length === 0) {
    reasonsNotReady.push('no changed files detected in git status input');
  }
  if (forbiddenPathHits.length > 0) {
    reasonsNotReady.push(`forbidden paths changed: ${forbiddenPathHits.join(', ')}`);
  }
  if (disallowedPathHits.length > 0) {
    reasonsNotReady.push(`changed files outside allowed paths: ${disallowedPathHits.join(', ')}`);
  }
  if (passClaims.length > 0 && commandEvidence.length === 0) {
    reasonsNotReady.push('agent report claims tests/checks passed but includes no recognizable test command evidence');
  }
  if (authorityTouches.length > 0) {
    reasonsNotReady.push('agent report references GYRE/verdict/classification authority; human approval required before commit readiness');
  }

  if (stagedFiles.length > 0) {
    advisoryNotes.push(`staged files detected for review: ${stagedFiles.join(', ')}`);
  } else {
    advisoryNotes.push('no staged files detected; this prototype remains read-only and does not stage files');
  }
  if (claimedCommits.length > 0) {
    advisoryNotes.push('agent report claims commits; verify git log before accepting custody claims');
  }

  return {
    repo: input.repo,
    current_branch: currentBranch,
    git_status_short: gitStatusShort,
    changed_files: changedFiles,
    staged_files: stagedFiles,
    forbidden_path_hits: Array.from(new Set(forbiddenPathHits)),
    claimed_tests: Array.from(new Set(claimedTests)),
    claimed_commits: Array.from(new Set(claimedCommits)),
    detected_human_approval_requests: Array.from(new Set(detectedHumanApprovalRequests)),
    commit_ready: reasonsNotReady.length === 0,
    reasons_not_ready: reasonsNotReady,
    advisory_notes: advisoryNotes,
  };
}
