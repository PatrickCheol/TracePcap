import { useEffect, useMemo, useState } from 'react';
import { conversationService } from '@/features/conversation/services/conversationService';
import type {
  DissectionNode,
  PacketDissection,
} from '@/features/conversation/types/packetDissection';
import {
  containsNasField,
  decodeFieldBits,
  fieldHex,
  filterDissection,
  findInitialField,
  hasFrameRange,
  isNasField,
} from './dissectionUtils';
import './PacketInspector.css';

const FRAME_PAGE_BYTES = 256;
const MAX_BIT_BYTES = 64;

interface PacketInspectorProps {
  conversationId: string;
  packetNumber: number;
}

type LoadState = {
  key: string;
  data?: PacketDissection;
  error?: string;
};

export function PacketInspector({ conversationId, packetNumber }: PacketInspectorProps) {
  const [attempt, setAttempt] = useState(0);
  const requestKey = `${conversationId}:${packetNumber}:${attempt}`;
  const [state, setState] = useState<LoadState>({ key: '' });

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    conversationService
      .getPacketDissection(conversationId, packetNumber, controller.signal)
      .then(data => {
        if (active) setState({ key: requestKey, data });
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return;
        const response = (error as { response?: { data?: { message?: string } } } | null)?.response;
        setState({
          key: requestKey,
          error:
            response?.data?.message ||
            'Could not decode this frame. Check that the original capture and packet decoder are available.',
        });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [conversationId, packetNumber, requestKey]);

  if (state.key !== requestKey || (!state.data && !state.error)) {
    return (
      <div className="packet-inspector pi-status" role="status">
        Decoding frame #{packetNumber}…
      </div>
    );
  }
  if (state.error) {
    return (
      <div className="packet-inspector pi-status" role="alert">
        <p>{state.error}</p>
        <button
          type="button"
          className="btn btn-sm btn-outline-secondary"
          onClick={() => setAttempt(value => value + 1)}
        >
          Retry packet decoding
        </button>
      </div>
    );
  }
  return <DissectionView key={requestKey} data={state.data!} />;
}

function FieldTree({
  nodes,
  selectedId,
  onSelect,
  searching = false,
  depth = 0,
}: {
  nodes: DissectionNode[];
  selectedId?: string;
  onSelect: (node: DissectionNode) => void;
  searching?: boolean;
  depth?: number;
}) {
  return (
    <ul className="pi-tree-list">
      {nodes.map(node => (
        <FieldTreeItem
          key={node.id}
          node={node}
          selectedId={selectedId}
          onSelect={onSelect}
          searching={searching}
          depth={depth}
        />
      ))}
    </ul>
  );
}

function FieldTreeItem({
  node,
  selectedId,
  onSelect,
  searching,
  depth,
}: {
  node: DissectionNode;
  selectedId?: string;
  onSelect: (node: DissectionNode) => void;
  searching: boolean;
  depth: number;
}) {
  const [open, setOpen] = useState(() => depth === 0 || containsNasField(node));
  const expanded = searching || open;
  return (
    <li>
      <div
        className={`pi-tree-row${selectedId === node.id ? ' pi-tree-row-selected' : ''}${isNasField(node) ? ' pi-tree-row-nas' : ''}`}
      >
        {node.children.length > 0 ? (
          <button
            type="button"
            className="pi-tree-toggle"
            aria-label={`${expanded ? 'Collapse' : 'Expand'} ${node.name || node.label}`}
            aria-expanded={expanded}
            onClick={() => setOpen(value => !value)}
          >
            <i className={`bi bi-chevron-${expanded ? 'down' : 'right'}`} aria-hidden="true" />
          </button>
        ) : (
          <span className="pi-tree-toggle-spacer" />
        )}
        <button
          type="button"
          className="pi-field-button"
          title={node.name}
          aria-pressed={selectedId === node.id}
          onClick={() => onSelect(node)}
        >
          {node.label || node.name}
        </button>
      </div>
      {expanded && node.children.length > 0 && (
        <FieldTree
          nodes={node.children}
          selectedId={selectedId}
          onSelect={onSelect}
          searching={searching}
          depth={depth + 1}
        />
      )}
    </li>
  );
}

function DissectionView({ data }: { data: PacketDissection }) {
  const [query, setQuery] = useState('');
  const initialField = useMemo(() => findInitialField(data.protocols, data.rawHex), [data]);
  const [selected, setSelected] = useState<DissectionNode | null>(initialField);
  const [framePage, setFramePage] = useState(() =>
    initialField && hasFrameRange(initialField, data.rawHex)
      ? Math.floor(initialField.byteOffset! / FRAME_PAGE_BYTES)
      : 0
  );
  const filtered = useMemo(() => filterDissection(data.protocols, query), [data.protocols, query]);
  const selectField = (node: DissectionNode) => {
    setSelected(node);
    if (hasFrameRange(node, data.rawHex))
      setFramePage(Math.floor(node.byteOffset! / FRAME_PAGE_BYTES));
  };
  const pageCount = Math.max(1, Math.ceil(data.rawHex.length / 2 / FRAME_PAGE_BYTES));
  const pageStart = framePage * FRAME_PAGE_BYTES;
  const pageHex = data.rawHex.slice(pageStart * 2, (pageStart + FRAME_PAGE_BYTES) * 2);
  const rows = pageHex.match(/.{1,32}/g) ?? [];
  const selectedInFrame = selected != null && hasFrameRange(selected, data.rawHex);

  return (
    <section
      className="packet-inspector"
      aria-label={`Packet details for frame ${data.packetNumber}`}
    >
      <div className="pi-heading">
        <strong>Frame #{data.packetNumber} · Packet details</strong>
        {data.nasDetected && <span className="pi-nas-badge">NAS decoded</span>}
        <small>{data.decoder}</small>
      </div>
      {data.warnings.length > 0 && (
        <ul className="pi-warnings">
          {data.warnings.map((warning, i) => (
            <li key={i}>{warning}</li>
          ))}
        </ul>
      )}
      <div className="pi-analysis-grid">
        <div className="pi-protocol-panel">
          <label className="pi-section-title" htmlFor={`packet-field-search-${data.packetNumber}`}>
            Protocol fields
          </label>
          <input
            id={`packet-field-search-${data.packetNumber}`}
            className="form-control form-control-sm pi-search"
            type="search"
            value={query}
            placeholder="Find a field, NAS, value…"
            onChange={event => setQuery(event.target.value)}
          />
          <div className="pi-tree" aria-label="Decoded protocol fields">
            {filtered.length > 0 ? (
              <FieldTree
                nodes={filtered}
                selectedId={selected?.id}
                onSelect={selectField}
                searching={query.trim().length > 0}
              />
            ) : (
              <p className="pi-muted">No decoded fields match this search.</p>
            )}
          </div>
        </div>
        <div className="pi-evidence-panel">
          {selected ? (
            <FieldEvidence node={selected} rawHex={data.rawHex} />
          ) : (
            <p className="pi-muted">
              No protocol fields were decoded. The captured bytes are available below.
            </p>
          )}
        </div>
      </div>
      <div className="pi-raw-panel">
        <div className="pi-raw-heading">
          <span>
            <strong>Original captured frame</strong>{' '}
            <small>
              {data.capturedLength.toLocaleString()} captured /{' '}
              {data.originalLength.toLocaleString()} wire bytes
            </small>
          </span>
          <div className="pi-paging">
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              aria-label="Previous frame bytes"
              disabled={framePage === 0}
              onClick={() => setFramePage(value => value - 1)}
            >
              Previous
            </button>
            <small>
              Bytes {pageStart.toLocaleString()}–
              {Math.max(
                pageStart,
                Math.min(pageStart + FRAME_PAGE_BYTES, data.rawHex.length / 2) - 1
              ).toLocaleString()}{' '}
              · {framePage + 1}/{pageCount}
            </small>
            <button
              type="button"
              className="btn btn-sm btn-outline-secondary"
              aria-label="Next frame bytes"
              disabled={framePage + 1 >= pageCount}
              onClick={() => setFramePage(value => value + 1)}
            >
              Next
            </button>
          </div>
        </div>
        <p className="pi-muted pi-raw-note">
          Select a field to highlight its bytes. Offsets are zero based; reassembled and generated
          fields use a separate source.
        </p>
        <div className="pi-hex-scroll">
          <pre className="pi-hex" aria-label="Original frame hex and ASCII">
            {rows.map((row, rowIndex) => {
              const bytes = row.match(/.{2}/g) ?? [];
              const offset = pageStart + rowIndex * 16;
              return (
                <span className="pi-hex-row" key={offset}>
                  <span className="pi-hex-offset">{offset.toString(16).padStart(6, '0')}</span>
                  {'  '}
                  <span className="pi-hex-values">
                    {bytes.map((byte, i) => {
                      const active =
                        selectedInFrame &&
                        offset + i >= selected!.byteOffset! &&
                        offset + i < selected!.byteOffset! + selected!.byteLength!;
                      return (
                        <span key={i}>
                          <span
                            className={active ? 'pi-byte-selected' : undefined}
                            data-byte-offset={offset + i}
                            title={`Byte ${offset + i} · 0x${byte}`}
                          >
                            {byte}
                          </span>
                          {i === 7 ? '  ' : ' '}
                        </span>
                      );
                    })}
                    {' '.repeat((16 - bytes.length) * 3 + (bytes.length <= 8 ? 1 : 0))}
                  </span>
                  {'  '}
                  <span className="pi-hex-ascii">
                    {bytes
                      .map(byte => {
                        const code = parseInt(byte, 16);
                        return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : '.';
                      })
                      .join('')}
                  </span>
                  {'\n'}
                </span>
              );
            })}
          </pre>
        </div>
      </div>
    </section>
  );
}

function FieldEvidence({ node, rawHex }: { node: DissectionNode; rawHex: string }) {
  const hex = fieldHex(node, rawHex);
  const limited = hex != null && hex.length / 2 > MAX_BIT_BYTES;
  const hasMask = node.bitmask != null && !/^(?:0x)?0+$/i.test(node.bitmask);
  // The decoder contract has no byte-order metadata. NAS uses network order; a
  // single octet has no endian ambiguity. Other multi-byte masks stay uninterpreted.
  const canInterpretMask = hex != null && (hex.length === 2 || isNasField(node));
  const applyMask = hasMask && canInterpretMask && !limited;
  const bits = hex
    ? decodeFieldBits(hex.slice(0, MAX_BIT_BYTES * 2), applyMask ? node.bitmask : null)
    : null;
  return (
    <section aria-label="Selected field evidence">
      <div className="pi-section-title">
        Selected field {isNasField(node) && <span className="pi-nas-badge">NAS</span>}
      </div>
      <strong className="pi-field-label">{node.label || node.name}</strong>
      <code className="pi-field-name">{node.name}</code>
      {node.description && <p className="pi-description">{node.description}</p>}
      <dl className="pi-field-metadata">
        <dt>Decoded value</dt>
        <dd>{node.displayValue ?? '—'}</dd>
        <dt>Byte source</dt>
        <dd>{node.source}</dd>
        <dt>Byte offset</dt>
        <dd>{node.byteOffset ?? 'Not available'}</dd>
        <dt>Byte length</dt>
        <dd>{node.byteLength ?? 'Not available'}</dd>
        <dt>Bit mask</dt>
        <dd>
          <code>{hasMask ? node.bitmask : 'Not supplied (raw octets)'}</code>
        </dd>
      </dl>
      {node.source !== 'frame' && (
        <p className="pi-source-note">
          {node.source === 'reassembled'
            ? 'This field belongs to a reassembled data source. Its offset is not a position in this original frame.'
            : node.source === 'generated'
              ? 'The decoder generated this field. It has no corresponding captured bytes.'
              : 'The decoder could not establish the byte source. No original-frame highlight is applied.'}
        </p>
      )}
      {bits ? (
        <>
          <div className="pi-bits-heading">
            Raw bytes → bits <small>MSB 7 → LSB 0</small>
          </div>
          <div className="pi-bits-scroll">
            <table className="pi-bits-table" aria-label="Selected field bytes and bits">
              <thead>
                <tr>
                  <th>Byte</th>
                  <th>Hex</th>
                  <th>7 6 5 4 3 2 1 0</th>
                </tr>
              </thead>
              <tbody>
                {bits.bytes.map((byte, i) => (
                  <tr key={i}>
                    <td>{node.byteOffset != null ? node.byteOffset + i : `+${i}`}</td>
                    <td>{byte}</td>
                    <td className="pi-bit-octet">
                      {parseInt(byte, 16)
                        .toString(2)
                        .padStart(8, '0')
                        .split('')
                        .map((bit, j) => (
                          <span
                            key={j}
                            className={
                              bits.selected[i][j] && applyMask ? 'pi-bit-selected' : undefined
                            }
                            title={`Bit ${7 - j}${bits.selected[i][j] && applyMask ? ' · selected by field mask' : ''}`}
                          >
                            {bit}
                          </span>
                        ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {applyMask && bits.maskValid && (
            <p className="pi-selected-bits">
              Field bits: <code>{bits.selectedBits}</code>
              {bits.selectedDecimal != null && <> · decimal {bits.selectedDecimal}</>}
            </p>
          )}
          {!limited && !hasMask && (
            <p className="pi-muted">
              Raw octet bits are shown. The decoder did not supply an exact field mask; individual
              field bit positions are not inferred.
            </p>
          )}
          {hasMask && !canInterpretMask && (
            <p className="pi-source-note">
              Byte-order metadata is unavailable for this multi-byte field. Raw bits and the decoder
              value are shown without interpreting its mask.
            </p>
          )}
          {!bits.maskValid && (
            <p className="pi-source-note">
              The decoder mask does not fit this field. Raw bits are shown without guessing bit
              positions.
            </p>
          )}
          {limited && (
            <p className="pi-muted">
              Showing the first {MAX_BIT_BYTES} bytes of this field. Select a child field for its
              individual value and mask.
            </p>
          )}
        </>
      ) : (
        <p className="pi-muted">
          Exact raw bytes are unavailable for this field. Bit positions are not inferred from its
          displayed value.
        </p>
      )}
    </section>
  );
}
