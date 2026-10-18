import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import LicensePanel from '../LicensePanel';
import type { LicenseInfo } from '../../utils/tauriLicense';

vi.mock('../../utils/tauriLicense', () => ({
  verifyLicense: vi.fn(async (_key: string): Promise<LicenseInfo> => {
    throw new Error('License activation is unavailable in this build');
  }),
}));

describe('LicensePanel fail-closed activation', () => {
  it('does not advertise or accept a universal owner bypass key', async () => {
    const activated = vi.fn();
    render(
      <LicensePanel
        isTrial={false}
        currentTier="free"
        activeLicense={null}
        onLicenseActivated={activated}
        onLicenseCleared={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    expect(screen.queryByText(/HH-OWNER-2026-ENTERPRISE/i)).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Enter License Key/i), {
      target: { value: 'candidate-entitlement' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Activate/i }));

    await waitFor(() => {
      expect(screen.getByText(/activation is unavailable/i)).toBeInTheDocument();
    });
    expect(activated).not.toHaveBeenCalled();
  });
});
