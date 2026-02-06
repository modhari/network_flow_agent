#This is based on the official sFlow v5 datagram format text.  ￼
#It decodes:
#	1.	Datagram header
#	2.	Flow samples (standard and expanded)
#	3.	Sampled header record
#	4.	Ethernet plus IPv4
#	5.	TCP or UDP ports

#It returns FlowRecord with latency_ms = 0.0 because sFlow sampling does not inherently carry latency. We can enrich later.
from __future__ import annotations

import ipaddress
import struct
import time
from typing import List, Optional, Tuple

from flow_agent_mcp.core.models import FlowRecord

# sFlow v5 spec text  [oai_citation:22‡sflow.org](https://sflow.org/SFLOW-DATAGRAM5.txt?utm_source=chatgpt.com)


def _u32_to_ipv4(v: int) -> str:
    return str(ipaddress.IPv4Address(v))


def _parse_ethernet_ipv4_ports(frame: bytes) -> Optional[Tuple[str, str, int, int, str]]:
    """
    Parse Ethernet plus IPv4 plus TCP or UDP ports from a sampled packet header.

    Returns:
      src_ip, dst_ip, src_port, dst_port, proto_str

    This is deliberately minimal. It will skip VLAN tags and IPv6 for now.
    """
    if len(frame) < 14:
        return None

    ether_type = struct.unpack_from("!H", frame, 12)[0]
    if ether_type != 0x0800:
        return None

    ip_off = 14
    if len(frame) < ip_off + 20:
        return None

    ver_ihl = frame[ip_off]
    version = ver_ihl >> 4
    if version != 4:
        return None

    ihl = (ver_ihl & 0x0F) * 4
    if len(frame) < ip_off + ihl:
        return None

    proto = frame[ip_off + 9]
    src_ip = _u32_to_ipv4(struct.unpack_from("!I", frame, ip_off + 12)[0])
    dst_ip = _u32_to_ipv4(struct.unpack_from("!I", frame, ip_off + 16)[0])

    l4_off = ip_off + ihl
    if proto in (6, 17):
        if len(frame) < l4_off + 4:
            return None
        src_port, dst_port = struct.unpack_from("!HH", frame, l4_off)
        proto_str = "TCP" if proto == 6 else "UDP"
        return src_ip, dst_ip, int(src_port), int(dst_port), proto_str

    return src_ip, dst_ip, 0, 0, str(int(proto))


def decode_sflow(data: bytes) -> List[FlowRecord]:
    """
    Decode an sFlow v5 datagram and extract FlowRecord from flow samples.

    Datagram header contains:
      version, agent_address, sub_agent_id, seq, sys_uptime, num_samples

    Then samples:
      sample_type_and_enterprise, sample_length, sample_data...

    For flow samples, we look for sampled_header record to extract a packet header.
    Spec references  [oai_citation:23‡sflow.org](https://sflow.org/SFLOW-DATAGRAM5.txt?utm_source=chatgpt.com)
    """
    if len(data) < 4:
        return []

    off = 0
    version = struct.unpack_from("!I", data, off)[0]
    off += 4
    if version != 5:
        return []

    # agent_address type: 1 = IPv4, 2 = IPv6
    if off + 4 > len(data):
        return []
    addr_type = struct.unpack_from("!I", data, off)[0]
    off += 4

    if addr_type == 1:
        if off + 4 > len(data):
            return []
        _agent_ipv4 = _u32_to_ipv4(struct.unpack_from("!I", data, off)[0])
        off += 4
    elif addr_type == 2:
        if off + 16 > len(data):
            return []
        off += 16
    else:
        return []

    if off + 20 > len(data):
        return []

    sub_agent_id = struct.unpack_from("!I", data, off)[0]
    off += 4
    _seq = struct.unpack_from("!I", data, off)[0]
    off += 4
    _sys_uptime = struct.unpack_from("!I", data, off)[0]
    off += 4
    num_samples = struct.unpack_from("!I", data, off)[0]
    off += 4

    flows: List[FlowRecord] = []
    ts = time.time()

    for _ in range(num_samples):
        if off + 8 > len(data):
            break

        sample_tag = struct.unpack_from("!I", data, off)[0]
        off += 4
        sample_len = struct.unpack_from("!I", data, off)[0]
        off += 4

        if off + sample_len > len(data):
            break

        sample = data[off : off + sample_len]
        off += sample_len

        enterprise = sample_tag >> 12
        sample_type = sample_tag & 0xFFF

        # enterprise 0 is standard sFlow
        if enterprise != 0:
            continue

        # Flow sample types for v5:
        # 1 flow_sample
        # 3 expanded_flow_sample
        if sample_type == 1:
            flows.extend(_decode_flow_sample(sample, ts))
        elif sample_type == 3:
            flows.extend(_decode_expanded_flow_sample(sample, ts))

    return flows


def _decode_flow_sample(sample: bytes, ts: float) -> List[FlowRecord]:
    """
    flow_sample:
      seq(4), source_id(4), sampling_rate(4), sample_pool(4),
      drops(4), input(4), output(4), record_count(4), records...

    Records:
      record_tag(4), record_len(4), record_data...

    We look for sampled_header record, which has standard enterprise 0 and format 1.
    Spec references  [oai_citation:24‡sflow.org](https://sflow.org/SFLOW-DATAGRAM5.txt?utm_source=chatgpt.com)
    """
    off = 0
    if len(sample) < 32:
        return []

    off += 4  # seq
    off += 4  # source_id
    off += 4  # sampling_rate
    off += 4  # sample_pool
    off += 4  # drops
    off += 4  # input
    off += 4  # output
    record_count = struct.unpack_from("!I", sample, off)[0]
    off += 4

    return _decode_flow_records(sample, off, record_count, ts)


def _decode_expanded_flow_sample(sample: bytes, ts: float) -> List[FlowRecord]:
    """
    expanded_flow_sample:
      seq(4), source_id_type(4), source_id_index(4),
      sampling_rate(4), sample_pool(4), drops(4),
      input_if_format(4), input_if_value(4),
      output_if_format(4), output_if_value(4),
      record_count(4), records...

    We still look for sampled_header records.
    """
    off = 0
    if len(sample) < 44:
        return []

    off += 4  # seq
    off += 4  # source_id_type
    off += 4  # source_id_index
    off += 4  # sampling_rate
    off += 4  # sample_pool
    off += 4  # drops
    off += 4  # input_if_format
    off += 4  # input_if_value
    off += 4  # output_if_format
    off += 4  # output_if_value
    record_count = struct.unpack_from("!I", sample, off)[0]
    off += 4

    return _decode_flow_records(sample, off, record_count, ts)


def _decode_flow_records(sample: bytes, off: int, record_count: int, ts: float) -> List[FlowRecord]:
    flows: List[FlowRecord] = []

    for _ in range(record_count):
        if off + 8 > len(sample):
            break

        record_tag = struct.unpack_from("!I", sample, off)[0]
        off += 4
        record_len = struct.unpack_from("!I", sample, off)[0]
        off += 4

        if off + record_len > len(sample):
            break

        record = sample[off : off + record_len]
        off += record_len

        enterprise = record_tag >> 12
        format_num = record_tag & 0xFFF

        # sampled_header is enterprise 0, format 1 in sFlow v5
        if enterprise == 0 and format_num == 1:
            fr = _decode_sampled_header(record, ts)
            if fr:
                flows.append(fr)

    return flows


def _decode_sampled_header(record: bytes, ts: float) -> Optional[FlowRecord]:
    """
    sampled_header:
      header_protocol(4), frame_length(4), stripped(4), header_length(4), header_bytes...

    header_protocol usually 1 for Ethernet.
    We parse Ethernet plus IPv4 and TCP or UDP ports.
    """
    if len(record) < 16:
        return None

    header_protocol = struct.unpack_from("!I", record, 0)[0]
    frame_length = struct.unpack_from("!I", record, 4)[0]
    # stripped = struct.unpack_from("!I", record, 8)[0]
    header_len = struct.unpack_from("!I", record, 12)[0]

    header = record[16 : 16 + header_len]
    if header_protocol != 1:
        return None

    parsed = _parse_ethernet_ipv4_ports(header)
    if not parsed:
        return None

    src_ip, dst_ip, src_port, dst_port, proto = parsed

    return FlowRecord(
        ts=ts,
        src=src_ip,
        dst=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        latency_ms=0.0,
        bytes=int(frame_length),
        packets=1,
    )
