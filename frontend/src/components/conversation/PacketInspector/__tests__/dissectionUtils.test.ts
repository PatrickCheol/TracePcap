import { describe, expect, it } from 'vitest';
import type { DissectionNode } from '@/features/conversation/types/packetDissection';
import { decodeFieldBits, fieldHex, filterDissection, hasFrameRange } from '../dissectionUtils';

const field = (overrides: Partial<DissectionNode> = {}): DissectionNode => ({
  id: 'registration',
  name: 'nas_5gs.mm.type',
  label: 'Registration type',
  displayValue: 'Initial registration (1)',
  rawValue: 'a1',
  byteOffset: 1,
  byteLength: 1,
  bitmask: '0x07',
  source: 'frame',
  description: null,
  children: [],
  ...overrides,
});

describe('packet field evidence', () => {
  it('extracts a low-nibble field without treating neighbouring bits as its value', () => {
    const bits = decodeFieldBits('ab', '0x0f');
    expect(bits.selected[0]).toEqual([false, false, false, false, true, true, true, true]);
    expect(bits.selectedBits).toBe('1011');
    expect(bits.selectedDecimal).toBe('11');
  });

  it('aligns a multi-byte mask from the most significant byte', () => {
    const bits = decodeFieldBits('abcd', '0x0f80');
    expect(bits.selectedBits).toBe('10111');
    expect(bits.selectedDecimal).toBe('23');
    expect(bits.selected[1]).toEqual([true, false, false, false, false, false, false, false]);
  });

  it('shows the whole octet for an unmasked field and rejects an oversized mask', () => {
    expect(decodeFieldBits('81', null).selectedBits).toBe('10000001');
    expect(decodeFieldBits('81', '0x100').maskValid).toBe(false);
    expect(decodeFieldBits('81', 'not-a-mask').selectedBits).toBeNull();
  });

  it('uses actual frame bytes for frame-relative fields', () => {
    expect(fieldHex(field({ rawValue: '99' }), '00a17e')).toBe('a1');
  });

  it('keeps reassembled offsets out of the original-frame highlight', () => {
    const node = field({ source: 'reassembled', rawValue: '7e' });
    expect(hasFrameRange(node, '001122')).toBe(false);
    expect(fieldHex(node, '001122')).toBe('7e');
  });

  it('does not invent raw bytes from generated or ambiguous displayed values', () => {
    expect(fieldHex(field({ source: 'generated' }), '00a17e')).toBeNull();
    expect(fieldHex(field({ source: 'unknown', rawValue: '1' }), '00a17e')).toBeNull();
    expect(hasFrameRange(field({ byteLength: 5 }), '00a17e')).toBe(false);
  });

  it('retains a matching NAS field and its protocol ancestors', () => {
    const tree = [
      field({
        id: 'root',
        name: 'ngap',
        label: 'NGAP',
        displayValue: null,
        rawValue: null,
        children: [
          field(),
          field({
            id: 'unrelated',
            name: 'ngap.procedureCode',
            label: 'Procedure',
            displayValue: '15',
          }),
        ],
      }),
    ];
    const matches = filterDissection(tree, 'INITIAL');
    expect(matches[0].name).toBe('ngap');
    expect(matches[0].children.map(node => node.id)).toEqual(['registration']);
    expect(filterDissection(tree, 'not present')).toEqual([]);
  });
});
