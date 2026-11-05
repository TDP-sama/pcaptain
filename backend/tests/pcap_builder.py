"""Build tiny pcap files in code, so tests never depend on downloaded captures."""

import struct
from pathlib import Path

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113  # "Linux cooked capture": fastscan does not understand it

DNS_QUERY = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")
SIP_OPTIONS = (
    b"OPTIONS sip:user@example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
    b"From: <sip:a@example.com>;tag=1\r\n"
    b"To: <sip:user@example.com>\r\n"
    b"Call-ID: 1@10.0.0.1\r\n"
    b"CSeq: 1 OPTIONS\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def ipv4_udp(sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    return header + udp


def ethernet(ip_packet: bytes) -> bytes:
    return bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00" + ip_packet


def linux_sll(ip_packet: bytes) -> bytes:
    # packet type, ARPHRD_ETHER, address length, 8-byte address, protocol = IPv4
    return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + ip_packet


def sip_frame() -> bytes:
    return ethernet(ipv4_udp(5060, 5060, SIP_OPTIONS))


def dns_frame() -> bytes:
    return ethernet(ipv4_udp(40000, 53, DNS_QUERY))


def write_pcap(path: Path, frames: list[bytes], linktype: int = LINKTYPE_ETHERNET) -> Path:
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, frame in enumerate(frames):
        data += struct.pack("<IIII", 1_700_000_000 + i, 0, len(frame), len(frame)) + frame
    path.write_bytes(data)
    return path
