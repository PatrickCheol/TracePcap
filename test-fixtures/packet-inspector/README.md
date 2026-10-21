# Packet inspector fixtures

All packets are generated locally from invented contents by
`scripts/generate_packet_inspector_fixtures.py` (Python standard library only).
There is no customer traffic, authentication material or real security key.
IP addresses use the documentation block `192.0.2.0/24`, names use
`example.test`, and the NAS identity uses test PLMN `001/01`.

Run from the repository root:

```sh
python3 scripts/generate_packet_inspector_fixtures.py
```

See `manifest.json` for frame-level descriptions. The captures are deterministic:

| Capture | Frames | Purpose |
| --- | --- | --- |
| `dns.pcap` | 2 | Ordinary request/response and direct byte offsets |
| `http-reassembled.pcap` | 6 | GET split across frames 4 and 5; the reconstructed HTTP message has offsets into its own data source |
| `nas-ngap.pcap` | 4 | Plain, integrity only, opaque ciphered, and new security context NAS headers inside real NGAP/SCTP envelopes |
| `truncated.pcap` | 1 | Captured NAS bytes shorter than the original wire length |

The four NGAP messages are decoder fixtures and do **not** form a valid live 5G
registration exchange. Integrity MACs are conspicuous dummy values. Frame 3's
opaque bytes are deterministic test data, not the output of a real cipher.
Neither fixture should be used to claim that cryptographic verification or
decryption succeeded.

The checked-in `.pdml` and `.jsonraw` files were produced by the local backend's
TShark **3.6.2**, without decode-as configuration. Their PCAP contents are wholly
synthetic. To regenerate (a real file, rather than stdin, is needed by `-2`):

```sh
docker cp test-fixtures/packet-inspector tracepcap-backend:/tmp/packet-inspector-fixtures
docker exec tracepcap-backend tshark -n -2 -r /tmp/packet-inspector-fixtures/nas-ngap.pcap -T pdml > test-fixtures/packet-inspector/nas-ngap.pdml
docker exec tracepcap-backend tshark -n -2 -r /tmp/packet-inspector-fixtures/nas-ngap.pcap -c 4 -Y 'frame.number==4' -T pdml > test-fixtures/packet-inspector/nas-security-mode-frame4.pdml
docker exec tracepcap-backend tshark -n -2 -r /tmp/packet-inspector-fixtures/nas-ngap.pcap -c 4 -Y 'frame.number==4' -T jsonraw -j frame > test-fixtures/packet-inspector/nas-security-mode-frame4.jsonraw
docker exec tracepcap-backend tshark -n -2 -r /tmp/packet-inspector-fixtures/http-reassembled.pcap -c 5 -Y 'frame.number==5' -T pdml > test-fixtures/packet-inspector/http-reassembled-frame5.pdml
docker exec tracepcap-backend tshark -n -2 -r /tmp/packet-inspector-fixtures/http-reassembled.pcap -c 5 -Y 'frame.number==5' -T jsonraw -j frame > test-fixtures/packet-inspector/http-reassembled-frame5.jsonraw
```

In HTTP frame 5, `http.request.method` has `pos="0" value="474554"`.
Those bytes start the **reassembled HTTP data**, whereas original frame offset 0
starts the Ethernet header (`020000…`). An inspector must not highlight these
offsets as original frame bytes. The NAS example's offsets, in contrast, are
direct mappings: the Security Mode Command's NAS PDU starts at frame offset 80,
its outer security-header octet is at 81 (`03`, low nibble), and the selected
NAS security-algorithm octet is at 90 (`22`, upper/lower nibbles).

`-T pdml -x` is unsupported in this TShark version. Original bytes are in the
JSONRAW `._source.layers.frame_raw[0]` string; `frame_raw[2]` is captured length.
