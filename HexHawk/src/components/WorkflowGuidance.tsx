import React from 'react';
import type { DisassemblyAnalysis } from '../App';
import { generateBinaryProfile } from '../utils/patternIntelligence';

interface WorkflowGuidanceProps {
  analysis: DisassemblyAnalysis;
  onNavigateToAddress?: (address: number) => void;
}

interface WorkflowStep {
  step: number;
  title: string;
  description: string;
  action?: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * Generate workflow steps based on binary profile
 */
function generateWorkflowSteps(analysis: DisassemblyAnalysis): WorkflowStep[] {
  const profile = generateBinaryProfile(analysis);
  const steps: WorkflowStep[] = [];

  // Step 1: Assess if packed
  if (profile.packedLikelihood > 60) {
    steps.push({
      step: 1,
      title: 'Identify Unpacking Routine',
      description:
        'Look for stack manipulation and control flow anomalies that indicate a packing stub.',
      action: 'Search for high-risk patterns',
      priority: 'critical',
    });
    steps.push({
      step: 2,
      title: 'Find Original Entry Point',
      description:
        'Trace through unpacking code to locate where control transfers to the real program.',
      action: 'Follow control flow',
      priority: 'critical',
    });
  }

  // Step 2: Anti-analysis measures
  if (profile.antiAnalysisDetected) {
    steps.push({
      step: steps.length + 1,
      title: 'Locate Anti-Analysis Code',
      description:
        'Identify debugger/VM detection and other anti-analysis techniques.',
      action: 'Review critical patterns',
      priority: 'critical',
    });
    steps.push({
      step: steps.length + 1,
      title: 'Bypass or Patch Defenses',
      description:
        'Consider dynamic analysis or patching anti-analysis checks.',
      action: 'Examine pattern details',
      priority: 'high',
    });
  }

  // Step 3: Obfuscation
  if (profile.obfuscationLevel === 'extreme' || profile.obfuscationLevel === 'high') {
    steps.push({
      step: steps.length + 1,
      title: 'Deobfuscate Key Functions',
      description:
        'Focus on high-value functions identified in pattern analysis.',
      action: 'Review medium-threat patterns',
      priority: 'high',
    });
  }

  // Step 4: Normal analysis path
  if (steps.length === 0) {
    steps.push({
      step: 1,
      title: 'Map Entry Points',
      description: 'Identify main() and key function entry points.',
      action: 'Review functions list',
      priority: 'medium',
    });
  }

  steps.push({
    step: steps.length + 1,
    title: 'Trace Key Call Chains',
    description: 'Follow important functions to understand program flow.',
    action: 'Use cross-references',
    priority: 'medium',
  });

  steps.push({
    step: steps.length + 1,
    title: 'Identify Critical Sections',
    description:
      'Look for algorithm implementation, crypto, or business logic.',
    action: 'Search patterns',
    priority: 'low',
  });

  return steps;
}

/**
 * Get color and icon for priority
 */
function getPriorityStyle(priority: string): { color: string; icon: string } {
  switch (priority) {
    case 'critical':
      return { color: '#F44336', icon: '🔴' };
    case 'high':
      return { color: '#FF9800', icon: '🟠' };
    case 'medium':
      return { color: '#FFC107', icon: '🟡' };
    case 'low':
      return { color: '#2196F3', icon: '🔵' };
    default:
      return { color: '#666', icon: '◆' };
  }
}

const WorkflowGuidance = React.memo(function WorkflowGuidance({
  analysis,
  onNavigateToAddress,
}: WorkflowGuidanceProps) {
  const steps = generateWorkflowSteps(analysis);
  const [expandedStep, setExpandedStep] = React.useState<number | null>(null);
  const primaryAddress = analysis.suspiciousPatterns?.[0]?.address;

  return (
    <div className="workflow-guidance">
      <div className="workflow-header">
        <h3>📋 Analysis Workflow</h3>
        <div className="workflow-subtitle">
          Recommended analysis sequence based on binary profile
        </div>
      </div>

      <div className="workflow-steps">
        {steps.map((step, index) => {
          const style = getPriorityStyle(step.priority);
          const isExpanded = expandedStep === step.step;

          return (
            <div
              key={index}
              className={`workflow-step ${step.priority} ${isExpanded ? 'expanded' : ''}`}
              style={{ borderLeftColor: style.color }}
            >
              <div
                className="step-header"
                onClick={() =>
                  setExpandedStep(isExpanded ? null : step.step)
                }
              >
                <div className="step-number" style={{ backgroundColor: style.color }}>
                  {step.step}
                </div>
                <div className="step-title-section">
                  <div className="step-title">{step.title}</div>
                  <div className="step-priority">
                    {style.icon} {step.priority.toUpperCase()}
                  </div>
                </div>
                <div className="step-toggle">
                  {isExpanded ? '▼' : '▶'}
                </div>
              </div>

              {isExpanded && (
                <div className="step-details">
                  <div className="step-description">{step.description}</div>
                  {step.action && (
                    <div className="step-action">
                      <button
                        className="action-button workflow-action wf-action"
                        data-address={typeof primaryAddress === 'number' ? primaryAddress : undefined}
                        style={{ borderColor: style.color, color: style.color }}
                        onClick={() => {
                          if (typeof primaryAddress === 'number' && onNavigateToAddress) {
                            onNavigateToAddress(primaryAddress);
                          }
                        }}
                      >
                        {step.action}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="workflow-footer">
        <div className="footer-note">
          💡 These steps adapt based on pattern detection. Review patterns in the right panel
          for detailed threat context.
        </div>
      </div>
    </div>
  );
});

export default WorkflowGuidance;
