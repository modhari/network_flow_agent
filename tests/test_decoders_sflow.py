import struct
from flow_agent_mcp.capabilities.sflow_udp.decoder import decode_sflow

def _build_ipv4_tcp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    # Ethernet header
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x11\x22\x33\x44\x55\x66"
    eth_type = b"\x08\x00"  # IPv4
    eth = dst_mac + src_mac + eth_type

    # IPv4 header, minimal, IHL 5, proto TCP
    ver_ihl = 0x45
    tos = 0
    total_len = 20 + 20
    ident = 0
    flags_frag = 0
    ttl = 64
    proto = 6
    checksum = 0

    def ip_to_u32(ip: str) -> int:
        parts = [int(p) for p in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    src_u32 = ip_to_u32(src_ip)
    dst_u32 = ip_to_u32(dst_ip)

    iphdr = struct.pack("!BBHHHBBHII",
        ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, checksum, src_u32, dst_u32
    )

    # TCP header minimal
    seq = 0
    ack = 0
    data_offset = 5 << 4
    flags = 0x02
    window = 8192
    check = 0
    urg = 0
    tcphdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset, flags, window, check, urg
    )

    return eth + iphdr + tcphdr

def _pad4(b: bytes) -> bytes:
    # sFlow records are aligned to 4 bytes
    pad = (-len(b)) % 4
    return b + (b"\x00" * pad)

def _build_sflow_v5_one_sample(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=443) -> bytes:
    # sampled_header record
    frame = _build_ipv4_tcp_frame(src_ip, dst_ip, src_port, dst_port)

    header_protocol = 1  # Ethernet
    frame_length = len(frame)
    stripped = 0
    header_len = len(frame)
    sampled_header = struct.pack("!IIII", header_protocol, frame_length, stripped, header_len) + frame
    sampled_header = _pad4(sampled_header)

    # record tag enterprise 0 format 1
    record_tag = (0 << 12) | 1
    record_len = len(sampled_header)
    record = struct.pack("!II", record_tag, record_len) + sampled_header

    # flow_sample
    seq = 1
    source_id = 0
    sampling_rate = 1
    sample_pool = 1
    drops = 0
    input_if = 0
    output_if = 0
    record_count = 1
    flow_sample = struct.pack("!IIIIIIII",
        seq, source_id, sampling_rate, sample_pool, drops, input_if, output_if, record_count
    ) + record

    # sample header
    sample_tag = (0 << 12) | 1
    sample_len = len(flow_sample)
    sample = struct.pack("!II", sample_tag, sample_len) + flow_sample

    # datagram header
    version = 5
    addr_type = 1
    agent_ip_u32 = (127 << 24) | 1
    sub_agent_id = 0
    seq_num = 1
    sys_uptime = 0
    num_samples = 1

    dgram = struct.pack("!II", version, addr_type)
    dgram += struct.pack("!I", agent_ip_u32)
    dgram += struct.pack("!IIII", sub_agent_id, seq_num, sys_uptime, num_samples)
    dgram += sample
    return dgram

def test_sflow_decoder_parses_tcp_tuple():
    data = _build_sflow_v5_one_sample()
    flows = decode_sflow(data)
    assert len(flows) == 1
    f = flows[0]
    assert f.src == "10.0.0.1"
    assert f.dst == "10.0.0.2"
    assert f.src_port == 1234
    assert f.dst_port == 443
    assert f.proto in ("TCP", "6")
    assert f.bytes > 0
    assert f.packets == 1
