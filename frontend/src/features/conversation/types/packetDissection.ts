/** Decoder evidence. Offsets are valid only in the source named by each node. */
export interface DissectionNode {
  id: string;
  name: string;
  label: string;
  displayValue: string | null;
  rawValue: string | null;
  byteOffset: number | null;
  byteLength: number | null;
  bitmask: string | null;
  source: 'frame' | 'reassembled' | 'generated' | 'unknown';
  description: string | null;
  children: DissectionNode[];
}

export interface PacketDissection {
  packetNumber: number;
  capturedLength: number;
  originalLength: number;
  rawHex: string;
  decoder: string;
  protocols: DissectionNode[];
  warnings: string[];
  nasDetected: boolean;
}
