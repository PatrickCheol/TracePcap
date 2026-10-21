import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { conversationService } from '@/features/conversation/services/conversationService';
import type {
  DissectionNode,
  PacketDissection,
} from '@/features/conversation/types/packetDissection';
import { PacketInspector } from '../PacketInspector';

const field = (overrides: Partial<DissectionNode> = {}): DissectionNode => ({
  id: 'nas-type',
  name: 'nas_5gs.mm.type',
  label: 'Registration type: Initial registration (1)',
  displayValue: 'Initial registration (1)',
  rawValue: 'a1',
  byteOffset: 2,
  byteLength: 1,
  bitmask: '0x07',
  source: 'frame',
  description: 'NAS registration type identifies the requested registration procedure.',
  children: [],
  ...overrides,
});

const packet = (overrides: Partial<PacketDissection> = {}): PacketDissection => ({
  packetNumber: 42,
  capturedLength: 4,
  originalLength: 4,
  rawHex: '7e00a141',
  decoder: 'TShark PDML',
  protocols: [
    field({
      id: 'nas',
      name: 'nas-5gs',
      label: 'Non-Access-Stratum 5GS',
      byteOffset: 0,
      byteLength: 4,
      bitmask: null,
      children: [field()],
    }),
  ],
  warnings: [],
  nasDetected: true,
  ...overrides,
});

afterEach(() => vi.restoreAllMocks());

describe('PacketInspector', () => {
  it('does not guess a generic multi-byte field mask without byte-order metadata', async () => {
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(
      packet({
        rawHex: '01000000',
        nasDetected: false,
        protocols: [
          field({
            name: 'smb2.flags.response',
            label: 'SMB2 Response: True',
            displayValue: 'True',
            rawValue: '01000000',
            byteOffset: 0,
            byteLength: 4,
            bitmask: '0x1',
            description: null,
          }),
        ],
      })
    );
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    await screen.findByText(/Byte-order metadata is unavailable for this multi-byte field/);
    const evidence = screen.getByLabelText('Selected field evidence');
    expect(evidence).toHaveTextContent('True');
    expect(evidence).toHaveTextContent('0x1');
    expect(evidence).not.toHaveTextContent('Field bits:');
    expect(evidence).not.toHaveTextContent('decimal');
    expect(
      screen.getByLabelText('Selected field bytes and bits').querySelector('.pi-bit-selected')
    ).toBeNull();
  });

  it('expands the NGAP ancestors of deeply nested NAS fields automatically', async () => {
    let nested = field({
      id: 'nas',
      name: 'nas-5gs',
      label: 'Non-Access-Stratum 5GS',
      children: [field()],
    });
    for (let depth = 7; depth >= 0; depth--) {
      nested = field({
        id: `ngap-container-${depth}`,
        name: `ngap.container_${depth}`,
        label: `NGAP ASN.1 container ${depth}`,
        displayValue: null,
        rawValue: null,
        bitmask: null,
        children: [nested],
      });
    }
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(
      packet({ protocols: [nested] })
    );
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    expect(
      await screen.findByRole('button', {
        name: 'Registration type: Initial registration (1)',
      })
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Registration type: Initial registration (1)' })
    ).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Selected field evidence')).toHaveTextContent(
      'Field bits: 001 · decimal 1'
    );
    expect(screen.getByRole('button', { name: 'Collapse ngap.container_7' })).toHaveAttribute(
      'aria-expanded',
      'true'
    );
  });

  it('initially selects a byte-backed NAS security header ahead of other NAS fields', async () => {
    const header = field({
      id: 'security-header',
      name: 'nas_5gs.security_header_type',
      label: 'Security header type: Integrity protected (1)',
      bitmask: '0x0f',
    });
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(
      packet({
        protocols: [
          field({
            id: 'nas-root',
            name: 'nas-5gs',
            label: 'NAS protocol',
            source: 'unknown',
            rawValue: null,
            children: [field(), header],
          }),
        ],
      })
    );
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    expect(
      await screen.findByRole('button', { name: 'Security header type: Integrity protected (1)' })
    ).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Selected field evidence')).toHaveTextContent(
      'Field bits: 0001 · decimal 1'
    );
  });

  it('labels raw octets honestly when the decoder does not supply a field mask', async () => {
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(
      packet({ protocols: [field({ bitmask: null })] })
    );
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    await screen.findByText(/The decoder did not supply an exact field mask/);
    expect(
      screen.getByLabelText('Selected field bytes and bits').querySelector('.pi-bit-selected')
    ).toBeNull();
    expect(screen.getByLabelText('Selected field evidence')).not.toHaveTextContent('Field bits:');
  });

  it('selects a NAS field and links its exact octet and masked bits', async () => {
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(packet());
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    expect(screen.getByRole('status')).toHaveTextContent('Decoding frame #42');
    await screen.findByRole('button', { name: 'Registration type: Initial registration (1)' });
    fireEvent.click(
      screen.getByRole('button', { name: 'Registration type: Initial registration (1)' })
    );
    expect(screen.getByLabelText('Selected field evidence')).toHaveTextContent(
      'Field bits: 001 · decimal 1'
    );
    expect(
      screen.getByText('NAS registration type identifies the requested registration procedure.')
    ).toBeInTheDocument();
    const frame = screen.getByLabelText('Original frame hex and ASCII');
    expect(frame.querySelector('[data-byte-offset="2"]')).toHaveClass('pi-byte-selected');
    expect(frame.querySelector('[data-byte-offset="1"]')).not.toHaveClass('pi-byte-selected');
    expect(
      screen.getByLabelText('Selected field bytes and bits').querySelectorAll('.pi-bit-selected')
    ).toHaveLength(3);
  });

  it('searches fields without losing the parent protocol', async () => {
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(packet());
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    await screen.findByLabelText('Protocol fields');
    fireEvent.change(screen.getByLabelText('Protocol fields'), { target: { value: 'initial' } });
    expect(screen.getByRole('button', { name: 'Non-Access-Stratum 5GS' })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Registration type: Initial registration (1)' })
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Protocol fields'), {
      target: { value: 'missing field' },
    });
    expect(screen.getByText('No decoded fields match this search.')).toBeInTheDocument();
  });

  it('shows reassembled bytes without highlighting an unrelated original-frame range', async () => {
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(
      packet({ protocols: [field({ source: 'reassembled', rawValue: '01' })] })
    );
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    await screen.findByText(/This field belongs to a reassembled data source/);
    expect(
      screen.getByLabelText('Original frame hex and ASCII').querySelector('.pi-byte-selected')
    ).toBeNull();
    expect(screen.getByLabelText('Selected field evidence')).toHaveTextContent(
      'Field bits: 001 · decimal 1'
    );
  });

  it('pages all frame bytes and jumps to a selected field beyond the first page', async () => {
    const hex = '00'.repeat(320) + 'a1' + '00'.repeat(191);
    vi.spyOn(conversationService, 'getPacketDissection').mockResolvedValue(
      packet({
        rawHex: hex,
        capturedLength: 512,
        originalLength: 512,
        protocols: [field({ byteOffset: 320 })],
      })
    );
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    await screen.findByRole('button', { name: 'Registration type: Initial registration (1)' });
    expect(
      screen.getByLabelText('Original frame hex and ASCII').querySelectorAll('[data-byte-offset]')
    ).toHaveLength(256);
    fireEvent.click(
      screen.getByRole('button', { name: 'Registration type: Initial registration (1)' })
    );
    expect(
      screen
        .getByLabelText('Original frame hex and ASCII')
        .querySelector('[data-byte-offset="320"]')
    ).toHaveClass('pi-byte-selected');
    expect(screen.getByRole('button', { name: 'Next frame bytes' })).toBeDisabled();
  });

  it('retries a failed decode without displaying an empty packet as a successful result', async () => {
    const get = vi
      .spyOn(conversationService, 'getPacketDissection')
      .mockRejectedValueOnce({ response: { data: { message: 'Original capture is missing' } } })
      .mockResolvedValueOnce(packet());
    render(<PacketInspector conversationId="conversation" packetNumber={42} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Original capture is missing');
    fireEvent.click(screen.getByRole('button', { name: 'Retry packet decoding' }));
    await screen.findByText('Frame #42 · Packet details');
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('aborts the old request and never replaces a new packet with a late response', async () => {
    let resolveFirst!: (value: PacketDissection) => void;
    let resolveSecond!: (value: PacketDissection) => void;
    const get = vi
      .spyOn(conversationService, 'getPacketDissection')
      .mockImplementationOnce(
        () =>
          new Promise(resolve => {
            resolveFirst = resolve;
          })
      )
      .mockImplementationOnce(
        () =>
          new Promise(resolve => {
            resolveSecond = resolve;
          })
      );
    const { rerender } = render(
      <PacketInspector conversationId="conversation" packetNumber={42} />
    );
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    const firstSignal = get.mock.calls[0][2];
    rerender(<PacketInspector conversationId="conversation" packetNumber={43} />);
    expect(firstSignal?.aborted).toBe(true);
    await act(async () => resolveSecond(packet({ packetNumber: 43 })));
    expect(screen.getByText('Frame #43 · Packet details')).toBeInTheDocument();
    await act(async () => resolveFirst(packet()));
    expect(screen.queryByText('Frame #42 · Packet details')).not.toBeInTheDocument();
    expect(screen.getByText('Frame #43 · Packet details')).toBeInTheDocument();
  });
});
