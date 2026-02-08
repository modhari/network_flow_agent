import struct
from flow_agent_mcp.capabilities.netflow_udp.decoder import decode_netflow

def _ip_to_u32(ip: str) -> int:
    a, b, c, d = [int(x) for x in ip.split(".")]
    return (a << 24) | (b << 16) | (c << 8) | d

def _build_netflow_v5_one_record(
    src="10.0.0.1", dst="10.0.0.2", src_port=1234, dst_port=80, proto=6, packets=7, bytes_=900
) -> bytes:
    version = 5
    count = 1
    sys_uptime = 0
    unix_secs = 1
    unix_nsecs = 0
    flow_seq = 1
    engine_type = 0
    engine_id = 0
    sampling = 0

    header = struct.pack("!HHIIIIBBH",
        version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling
    )

    src_u32 = _ip_to_u32(src)
    dst_u32 = _ip_to_u32(dst)
    nexthop = 0
    input_if = 0
    output_if = 0
    first = 0
    last = 0
    tos = 0
    tcp_flags = 0
    pad1 = 0
    src_as = 0
    dst_as = 0
    src_mask = 0
    dst_mask = 0
    pad2 = 0

    rec = struct.pack("!IIIHHIIIIHHBBBBHHBBH",
        src_u32, dst_u32, nexthop,
        input_if, output_if,
        packets, bytes_,
        first, last,
        src_port, dst_port,
        pad1, tcp_flags, proto, tos,
        0, 0,
        src_as, dst_as,
        src_mask, dst_mask,
        pad2
    )
    # Above packing is tricky, so simplest is to force correct record length by padding
    # NetFlow v5 record must be 48 bytes
    rec = rec[:48].ljust(48, b"\x00")
    return header + rec

def test_netflow_v5_decoder_parses_one_record():
    data = _build_netflow_v5_one_record()
    flows = decode_netflow(data, exporter="1.2.3.4")
    assert len(flows) == 1
    f = flows[0]
    assert f.src == "10.0.0.1"
    assert f.dst == "10.0.0.2"
    assert f.src_port == 1234
    assert f.dst_port == 80
    assert f.bytes == 900
    assert f.packets == 7

def _build_netflow_v9_template_and_data(exporter_ip="1.2.3.4"):
    # NetFlow v9 header
    version = 9
    count = 2
    sys_uptime = 0
    unix_secs = 1
    seq = 1
    source_id = 42

    header = struct.pack("!HHIIII",
        version, count, sys_uptime, unix_secs, seq, source_id
    )

    # Template FlowSet (id 0)
    # Template id 256, fields: srcIPv4(8,4) dstIPv4(12,4) srcPort(7,2) dstPort(11,2) proto(4,1) bytes(1,4) packets(2,4)
    template_id = 256
    fields = [
        (8, 4),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 4),
        (2, 4),
    ]
    template_rec = struct.pack("!HH", template_id, len(fields))
    for ftype, flen in fields:
        template_rec += struct.pack("!HH", ftype, flen)
    # Pad to 4 byte boundary inside flowset
    pad = (-len(template_rec)) % 4
    template_body = template_rec + (b"\x00" * pad)
    template_flowset = struct.pack("!HH", 0, 4 + len(template_body)) + template_body

    # Data FlowSet where flowset_id equals template_id
    src = _ip_to_u32("10.0.0.1")
    dst = _ip_to_u32("10.0.0.2")
    src_port = 1234
    dst_port = 443
    proto = 6
    bytes_ = 1000
    packets = 10

    data_rec = struct.pack("!IIHHBII", src, dst, src_port, dst_port, proto, bytes_, packets)
    data_rec = data_rec[:sum(f[1] for f in fields)].ljust(sum(f[1] for f in fields), b"\x00")
    data_flowset = struct.pack("!HH", template_id, 4 + len(data_rec)) + data_rec

    return header + template_flowset + data_flowset, source_id

def test_netflow_v9_template_and_data_decodes():
    data, _source_id = _build_netflow_v9_template_and_data()
    flows = decode_netflow(data, exporter="1.2.3.4")
    assert len(flows) == 1
    f = flows[0]
    assert f.src == "10.0.0.1"
    assert f.dst == "10.0.0.2"
    assert f.src_port == 1234
    assert f.dst_port == 443
    assert f.bytes == 1000
    assert f.packets == 10
