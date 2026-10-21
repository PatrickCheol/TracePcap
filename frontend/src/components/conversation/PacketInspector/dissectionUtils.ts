import type { DissectionNode } from '@/features/conversation/types/packetDissection';

export const isNasField = (node: DissectionNode): boolean =>
  /^(nas[-_.]5gs|nas[-_.]eps|nas[-_.]5g|nas)([._-]|$)/i.test(node.name);

/** NAS can be nested inside several NGAP ASN.1 containers. Keep that path visible. */
export const containsNasField = (node: DissectionNode): boolean =>
  isNasField(node) || node.children.some(containsNasField);

/** Keep matching fields and their ancestors, so a match retains its protocol context. */
export function filterDissection(nodes: DissectionNode[], query: string): DissectionNode[] {
  const term = query.trim().toLowerCase();
  if (!term) return nodes;
  return nodes.flatMap(node => {
    if (
      [node.name, node.label, node.displayValue, node.rawValue].some(value =>
        value?.toLowerCase().includes(term)
      )
    ) {
      return [node];
    }
    const children = filterDissection(node.children, term);
    return children.length ? [{ ...node, children }] : [];
  });
}

export function findInitialField(nodes: DissectionNode[], rawHex: string): DissectionNode | null {
  const flatten = (fields: DissectionNode[]): DissectionNode[] =>
    fields.flatMap(node => [node, ...flatten(node.children)]);
  const nasFields = flatten(nodes).filter(isNasField);
  const usableLeaves = nasFields.filter(
    node => node.children.length === 0 && fieldHex(node, rawHex) != null
  );
  return (
    usableLeaves.find(node => /\.security_header_type$/.test(node.name)) ??
    usableLeaves[0] ??
    nasFields[0] ??
    nodes[0] ??
    null
  );
}

export function hasFrameRange(node: DissectionNode, rawHex: string): boolean {
  return (
    node.source === 'frame' &&
    node.byteOffset != null &&
    node.byteOffset >= 0 &&
    node.byteLength != null &&
    node.byteLength > 0 &&
    node.byteOffset + node.byteLength <= rawHex.length / 2
  );
}

/** Never apply reassembled/generated source offsets to the captured frame. */
export function fieldHex(node: DissectionNode, rawHex: string): string | null {
  if (hasFrameRange(node, rawHex)) {
    return rawHex.slice(node.byteOffset! * 2, (node.byteOffset! + node.byteLength!) * 2);
  }
  const value = node.rawValue?.replace(/^0x/i, '');
  // Numeric display values can also look like hex. Require the decoder's exact byte width.
  if (
    node.source !== 'generated' &&
    value &&
    /^[\da-f]+$/i.test(value) &&
    node.byteLength != null &&
    node.byteLength > 0 &&
    value.length === node.byteLength * 2
  ) {
    return value;
  }
  return null;
}

export interface FieldBits {
  bytes: string[];
  /** Per-byte booleans in displayed MSB -> LSB order. */
  selected: boolean[][];
  selectedBits: string | null;
  selectedDecimal: string | null;
  maskValid: boolean;
}

/** Apply masks in network (MSB-first) order. Callers must establish the field's byte order. */
export function decodeFieldBits(hex: string, mask: string | null): FieldBits {
  const bytes = hex.match(/.{2}/g) ?? [];
  let parsedMask: bigint | null = null;
  let maskValid = true;
  if (mask && !/^0x0+$/i.test(mask) && !/^0+$/.test(mask)) {
    try {
      parsedMask = BigInt(mask);
      maskValid = parsedMask > 0n && parsedMask < 1n << BigInt(bytes.length * 8);
    } catch {
      maskValid = false;
    }
  }
  const selected = bytes.map((_, byteIndex) =>
    Array.from({ length: 8 }, (_, bitIndex) => {
      if (!maskValid) return false;
      if (parsedMask == null) return true;
      const shift = BigInt((bytes.length - byteIndex - 1) * 8 + (7 - bitIndex));
      return (parsedMask & (1n << shift)) !== 0n;
    })
  );
  const selectedBits = maskValid
    ? bytes
        .map((byte, i) =>
          parseInt(byte, 16)
            .toString(2)
            .padStart(8, '0')
            .split('')
            .filter((_, j) => selected[i][j])
            .join('')
        )
        .join('')
    : null;
  return {
    bytes,
    selected,
    selectedBits,
    selectedDecimal:
      selectedBits && selectedBits.length <= 64 ? BigInt(`0b${selectedBits}`).toString() : null,
    maskValid,
  };
}
