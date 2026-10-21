import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { StoryAggregates } from '@/types';
import { AggregatesPanel } from '../AggregatesPanel';

const base: StoryAggregates = {
  coverage: {
    totalConversations: 1,
    shownConversations: 0,
    totalPackets: 4,
    shownPackets: 0,
    bytesCoveragePct: 0,
  },
  topExternalAsns: [
    { asn: null, org: 'Unknown', country: null, bytes: 520, pct: 100, flowCount: 1 },
  ],
  protocolRiskMatrix: [{ protocol: 'NGAP/NAS-5GS', total: 1, atRisk: 0 }],
  tlsAnomalySummary: { selfSigned: 0, expired: 0, unknownCa: 0, total: 0 },
  unknownAppPct: null,
  beaconCandidates: [],
};

describe('AggregatesPanel unavailable metrics', () => {
  it.each([null, undefined, NaN])(
    'renders an unavailable unknown-application percentage as N/A (%s)',
    value => {
      render(<AggregatesPanel aggregates={{ ...base, unknownAppPct: value }} />);
      const unknownApp = screen.getByText('Unknown App').parentElement!;
      expect(unknownApp).toHaveTextContent('N/A');
      expect(unknownApp).not.toHaveTextContent('0.0%');
      expect(screen.getByText('NGAP/NAS-5GS')).toBeVisible();
    }
  );

  it('preserves a measured zero as 0.0%, distinct from unavailable data', () => {
    render(<AggregatesPanel aggregates={{ ...base, unknownAppPct: 0 }} />);
    expect(screen.getByText('Unknown App').parentElement).toHaveTextContent('0.0%');
  });

  it('guards missing ASN percentages and beacon jitter from an incomplete stored response', () => {
    // Exercise wire values from a partial/older response, even where the current contract uses numbers.
    const stored: StoryAggregates = JSON.parse(
      JSON.stringify({
        ...base,
        topExternalAsns: [{ ...base.topExternalAsns[0], pct: null }],
        beaconCandidates: [
          {
            srcIp: '192.0.2.30',
            dstIp: '192.0.2.40',
            dstPort: null,
            protocol: 'SCTP',
            appName: null,
            flowCount: 3,
            avgIntervalMs: null,
            cv: null,
          },
        ],
      })
    );
    render(<AggregatesPanel aggregates={stored} />);
    expect(screen.getByRole('cell', { name: 'N/A' })).toBeVisible();
    expect(screen.getByText('jitter', { exact: false }).parentElement).toHaveTextContent('N/A');
    expect(screen.queryByText(/NaN%|null%/)).not.toBeInTheDocument();
  });
});
