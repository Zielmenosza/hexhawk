import React from 'react';
import type { ReferenceStrength } from '../App';

interface ReferenceStrengthBadgeProps {
  strength: ReferenceStrength;
  interactive?: boolean;
  onClick?: () => void;
  size?: 'small' | 'medium' | 'large';
}

const ReferenceStrengthBadge: React.FC<ReferenceStrengthBadgeProps> = React.memo(
  ({ strength, interactive = false, onClick, size = 'medium' }) => {
    const getColor = (importance: string) => {
      switch (importance) {
        case 'critical':
          return { bg: '#F44336', text: '#fff', border: '#D32F2F' };
        case 'high':
          return { bg: '#FFC107', text: '#000', border: '#FFA000' };
        case 'medium':
          return { bg: '#2196F3', text: '#fff', border: '#1976D2' };
        case 'low':
          return { bg: '#9E9E9E', text: '#fff', border: '#757575' };
        default:
          return { bg: '#757575', text: '#fff', border: '#616161' };
      }
    };

    const getIcon = (importance: string) => {
      switch (importance) {
        case 'critical':
          return '❗';
        case 'high':
          return '⬇️';
        case 'medium':
          return '→';
        case 'low':
          return '•';
        default:
          return '?';
      }
    };

    const getSizeClass = () => {
      switch (size) {
        case 'small':
          return 'badge-small';
        case 'large':
          return 'badge-large';
        default:
          return 'badge-medium';
      }
    };

    const colors = getColor(strength.importance);

    return (
      <button
        className={`ref-strength-badge ${getSizeClass()} ${interactive ? 'interactive' : ''} ref-strength-${strength.importance}`}
        onClick={onClick}
        disabled={!interactive}
        style={{
          backgroundColor: colors.bg,
          color: colors.text,
          border: `2px solid ${colors.border}`,
        }}
        title={`${strength.importance.toUpperCase()}: ${strength.incomingCount} incoming, ${strength.outgoingCount} outgoing`}
      >
        <span className="badge-icon">{getIcon(strength.importance)}</span>
        <span className="badge-text">
          {strength.incomingCount}
          <span className="badge-separator">/</span>
          {strength.outgoingCount}
        </span>
      </button>
    );
  }
);

ReferenceStrengthBadge.displayName = 'ReferenceStrengthBadge';

export default ReferenceStrengthBadge;
