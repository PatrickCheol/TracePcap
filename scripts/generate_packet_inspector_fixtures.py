#!/usr/bin/env python3
"""Generate tiny, deterministic inspector captures using only the standard library.

All addresses, identities and payloads are invented. No network access, captured
customer traffic, credentials, dependencies or real cryptographic secrets are used.
"""

import ipaddress
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "test-fixtures" / "packet-inspector"
ETHER = bytes.fromhex("0200000000020200000000010800")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(payload, proto, src="192.0.2.10", dst="192.0.2.20", ident=1):
    src_bytes = ipaddress.ip_address(src).packed
    dst_bytes = ipaddress.ip_address(dst).packed
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                       0x4000, 64, proto, 0, src_bytes, dst_bytes)
    return ETHER + head[:10] + struct.pack("!H", checksum(head)) + head[12:] + payload


def udp(payload, sport=53000, dport=53, reverse=False):
    if reverse:
        sport, dport = dport, sport
    head = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return ipv4(head + payload, 17, *(["192.0.2.20", "192.0.2.10"] if reverse else []))


def tcp(payload=b"", seq=1, ack=1, flags=0x18, reverse=False):
    src, dst = (["192.0.2.20", "192.0.2.10"] if reverse
                else ["192.0.2.10", "192.0.2.20"])
    sport, dport = (80, 45000) if reverse else (45000, 80)
    head = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    pseudo += struct.pack("!BBH", 0, 6, len(head) + len(payload))
    head = head[:16] + struct.pack("!H", checksum(pseudo + head + payload)) + head[18:]
    return ipv4(head + payload, 6, src, dst)


def crc32c(data):
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for unused in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def ngap(nas):
    # Aligned PER InitialUEMessage: RAN-UE-NGAP-ID, NAS-PDU, NR location,
    # RRC establishment cause and UE context request. Lengths are short-form.
    # PLMN 001/01 and locally invented identifiers are for tests only.
    def ie(number, criticality, value):
        return struct.pack("!HBB", number, criticality, len(value)) + value

    fields = [ie(85, 0x00, b"\x00\x01"),
              ie(38, 0x00, bytes([len(nas)]) + nas),
              ie(121, 0x00, bytes.fromhex("4000f110000000001000f110000001")),
              ie(90, 0x40, b"\x10"), ie(112, 0x40, b"\x00")]
    body = b"\x00\x00\x05" + b"".join(fields)
    return b"\x00\x0f\x40" + bytes([len(body)]) + body


def sctp(nas, tsn=1):
    payload = ngap(nas)
    data = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn - 1, 60) + payload
    data += b"\x00" * ((-len(data)) % 4)
    head = struct.pack("!HHII", 50000, 38412, 0x10203040, 0)
    packet = head + data
    packet = packet[:8] + struct.pack("<I", crc32c(packet)) + packet[12:]
    return ipv4(packet, 132, "192.0.2.30", "192.0.2.40", tsn)


def write_pcap(name, packets):
    with (ROOT / name).open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            if isinstance(packet, tuple):
                packet, original_length = packet
            else:
                original_length = len(packet)
            out.write(struct.pack("<IIII", 1700000000, index * 10000,
                                  len(packet), original_length))
            out.write(packet)


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    question = b"\x07example\x04test\x00\x00\x01\x00\x01"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    answer = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question
    answer += bytes.fromhex("c00c000100010000003c0004c0000263")
    dns_packets = [udp(query), udp(answer, reverse=True)]
    write_pcap("dns.pcap", dns_packets)
    request = b"GET /inspector HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    write_pcap("http-reassembled.pcap", [
        tcp(seq=100, ack=0, flags=2), tcp(seq=500, ack=101, flags=0x12, reverse=True),
        tcp(seq=101, ack=501, flags=0x10), tcp(request[:12], seq=101, ack=501),
        tcp(request[12:], seq=113, ack=501),
        tcp(response, seq=501, ack=101 + len(request), reverse=True)])
    plain = bytes.fromhex("7e004179000c0100f110f0ff0000000000011001072e04e0e00000")
    integrity = bytes.fromhex("7e01deadbeef007e0043")
    ciphered = bytes.fromhex("7e02010203040100112233445566778899aabbccddeeff")
    security_mode = bytes.fromhex("7e03aabbccdd007e005d220002e0e0")
    nas_packets = [sctp(data, n + 1) for n, data in enumerate(
        [plain, integrity, ciphered, security_mode])]
    write_pcap("nas-ngap.pcap", nas_packets)
    write_pcap("truncated.pcap", [(nas_packets[0][:90], len(nas_packets[0]))])
    manifest = {
        "provenance": "Generated locally by scripts/generate_packet_inspector_fixtures.py; all contents synthetic.",
        "dns.pcap": {"frames": 2, "purpose": "Simple DNS request and response; example.test uses documentation addresses."},
        "http-reassembled.pcap": {"frames": 6, "purpose": "HTTP GET split across frames 4 and 5 to exercise reassembly and uncertain source offsets."},
        "nas-ngap.pcap": {
            "frames": 4, "purpose": "SCTP PPID 60 → NGAP InitialUEMessage → NAS-5GS; no decode-as rules needed.",
            "1": "Plain registration request, initial registration+FOR+ngKSI 7, fake SUCI 001/01.",
            "2": "Integrity-only outer header with clear Registration Complete, deliberately invalid dummy MAC deadbeef.",
            "3": "Ciphered outer header with deterministic opaque payload; not real encryption and must not be presented as recovered plaintext.",
            "4": "Integrity-protected new context Security Mode Command; NEA2+NIA2, deliberately invalid dummy MAC aabbccdd.",
            "warning": "NAS bodies test decoding only; four InitialUEMessage envelopes do not form a valid live registration procedure or security context."},
        "truncated.pcap": {"frames": 1, "purpose": "Snaplen-truncated NAS frame: original wire length exceeds stored bytes."}}
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Generated inspector fixtures in", ROOT)


if __name__ == "__main__":
    main()
