import struct
from flow_agent_mcp.capabilities.ipfix_udp.decoder import decode_ipfix

def _ip_to_bytes(ip: str) -> bytes:
    a, b, c, d = [int(x) for x in ip.split(".")]
    return bytes([a, b, c, d])

def test_ipfix_template_and_data_decodes():
    version = 10
    export_time = 1
    seq = 1
    obs_domain = 256

    # Template set id 2
    template_id = 256
    fields = [
        (8, 4),   # sourceIPv4Address
        (12, 4),  # destinationIPv4Address
        (7, 2),   # sourceTransportPort
        (11, 2),  # destinationTransportPort
        (4, 1),   # protocolIdentifier
        (1, 4),   # octetDeltaCount
        (2, 4),   # packetDeltaCount
    ]
    tmpl_rec = struct.pack("!HH", template_id, len(fields))
    for ie, flen in fields:
        tmpl_rec += struct.pack("!HH", ie, flen)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl_rec)) + tmpl_rec

    # Data set id equals template id
    src = _ip_to_bytes("10.0.0.1")
    dst = _ip_to_bytes("10.0.0.2")
    src_port = 1234
    dst_port = 53
    proto = 17
    bytes_ = 500
    packets = 5

    data_rec = src + dst
    data_rec += struct.pack("!HH", src_port, dst_port)
    data_rec += struct.pack("!B", proto)
    data_rec += struct.pack("!I", bytes_)
    data_rec += struct.pack("!I", packets)

    data_set = struct.pack("!HH", template_id, 4 + len(data_rec)) + data_rec

    # IPFIX message header, length computed
    body = tmpl_set + data_set
    length = 16 + len(body)
    header = struct.pack("!HHIII", version, length, export_time, seq, obs_domain)

    msg = header + body

    flows = decode_ipfix(msg, exporter="1.2.3.4")
    assert len(flows) == 1
    f = flows[0]
    assert f.src == "10.0.0.1"
    assert f.dst == "10.0.0.2"
    assert f.src_port == 1234
    assert f.dst_port == 53
    assert f.bytes == 500
    assert f.packets == 5
