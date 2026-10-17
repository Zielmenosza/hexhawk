import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import AuthorityBanner from '../AuthorityBanner';
import { copy } from '../../content/productLanguage';

describe('AuthorityBanner', () => {
  it('renders advisory banner copy', () => {
    render(<AuthorityBanner />);

    expect(screen.getByTestId('authority-banner')).toBeTruthy();
    expect(screen.getByText(copy.advisory)).toBeTruthy();
    expect(screen.getByText(/File assessment is based only on HexHawk’s verified analysis signals/)).toBeTruthy();
    expect(screen.getByText(/Runtime evidence adds context when available/)).toBeTruthy();
  });

  it('hides when flag false', () => {
    const { container } = render(<AuthorityBanner enabled={false} />);

    expect(screen.queryByTestId('authority-banner')).toBeNull();
    expect(container.firstChild).toBeNull();
  });

  it('matches the default advisory banner snapshot', () => {
    const { container } = render(<AuthorityBanner />);

    expect(container.firstChild).toMatchSnapshot();
  });
});
