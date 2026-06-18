import { flags } from '../config/featureFlags';
import { copy } from '../content/productLanguage';

export interface AuthorityBannerProps {
  enabled?: boolean;
}

export default function AuthorityBanner({ enabled = flags.clarityAuthorityBanner }: AuthorityBannerProps) {
  if (!enabled) return null;

  return (
    <section
      aria-label="HexHawk authority boundary"
      data-testid="authority-banner"
      style={{
        border: '1px solid rgba(125, 211, 252, 0.45)',
        borderRadius: '12px',
        padding: '0.85rem 1rem',
        margin: '0.75rem 1rem',
        background: 'rgba(14, 165, 233, 0.08)',
        color: 'inherit',
      }}
    >
      <strong>{copy.advisory}</strong>
      <span>{` · ${copy.verdict} remains the authority.`}</span>
      <span>{` ${copy.runtime} is supporting context.`}</span>
    </section>
  );
}
