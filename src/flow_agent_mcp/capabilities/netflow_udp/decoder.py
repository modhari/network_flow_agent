from __future__ import annotations

import ipaddress
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from flow_agent_mcp.core.models import FlowRecord

# References
# NetFlow v5 and earlier datagram formats, Cisco docs  [oai_citation:5‡Cisco](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html?utm_source=chatgpt.com)
# NetFlow v9 templates and FlowSets, RFC 3954  [oai_citation:6‡IETF](https://www.ietf.org/rfc/rfc3954.txt?utm_source=chatgpt.com)


def _ipv4_from_u32(v: int) -> str:
    return str(ipaddress.IPv4Address(v))


@dataclass
class _TemplateField:
    field_type: int
    field_len: int


@dataclass
class _Template:
    template_id: int
    fields: List[_TemplateField]


class NetFlowV9TemplateCache:
    """
    Template cache keyed by exporter identity and source id.
    NetFlow v9 uses templates (FlowSet ID 0 for templates)  [oai_citation:7‡IETF](https://www.ietf.org/rfc/rfc3954.txt?utm_source=chatgpt.com)
    """

    def __init__(self):
        self._templates: Dict[Tuple[str, int], Dict[int, _Template]] = {}

    def put(self, exporter: str, source_id: int, template: _Template) -> None:
        self._templates.setdefault((exporter, source_id), {})[template.template_id] = template

    def get(self, exporter: str, source_id: int, template_id: int) -> Optional[_Template]:
        return self._templates.get((exporter, source_id), {}).get(template_id)


# Module level cache so the decoder retains templates across packets
_V9_CACHE = NetFlowV9TemplateCache()


# Field type IDs for NetFlow v9 and IPFIX overlap heavily, but are not identical for all fields.
# We implement only the essentials needed to build a 5 tuple and counters.
# See Cisco and IANA references for field meanings.  [oai_citation:8‡Cisco](https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html?utm_source=chatgpt.com)
NFV9_FIELD = {
    8: "src_ipv4",
    12: "dst_ipv4",
    7: "src_port",
    11: "dst_port",
    4: "proto",
    1: "bytes",
    2: "packets",
}


def decode_netflow(data: bytes, exporter: str = "unknown") -> List[FlowRecord]:
    """
    Decode NetFlow v5 or v9 packet into FlowRecord objects.

    exporter
      String identity for template cache key. In the UDP capability you should pass
      the sender IP address from recvfrom.
    """
    if len(data) < 2:
        return []

    version = struct.unpack_from("!H", data, 0)[0]
    if version == 5:
        return _decode_v5(data)
    if version == 9:
        return _decode_v9(data, exporter)
    return []


def _decode_v5(data: bytes) -> List[FlowRecord]:
    """
    NetFlow v5 format:
    Header is 24 bytes, followed by count flow records, each 48 bytes.
    Cisco NetFlow v5 format references  [oai_citation:9‡Cisco](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html?utm_source=chatgpt.com)
    """
    if len(data) < 24:
        return []

    # v5 header:
    # version(2), count(2), sysUpTime(4), unix_secs(4), unix_nsecs(4),
    # flow_sequence(4), engine_type(1), engine_id(1), sampling_interval(2)
    version, count = struct.unpack_from("!HH", data, 0)
    if version != 5:
        return []

    # unix_secs is at offset 8
    unix_secs = struct.unpack_from("!I", data, 8)[0]
    ts = float(unix_secs) if unix_secs else time.time()

    records_offset = 24
    record_size = 48
    flows: List[FlowRecord] = []

    # Protect against malformed count
    max_records = max(0, (len(data) - records_offset) // record_size)
    count = min(count, max_records)

    for i in range(count):
        off = records_offset + i * record_size

        # v5 record layout (selected fields):
        # srcaddr(4), dstaddr(4), nexthop(4),
        # input(2), output(2),
        # dPkts(4), dOctets(4),
        # First(4), Last(4),
        # srcport(2), dstport(2),
        # pad1(1), tcp_flags(1), prot(1), tos(1), ...
        src_u32, dst_u32 = struct.unpack_from("!II", data, off)
        dpkts = struct.unpack_from("!I", data, off + 16)[0]
        doctets = struct.unpack_from("!I", data, off + 20)[0]
        src_port = struct.unpack_from("!H", data, off + 32)[0]
        dst_port = struct.unpack_from("!H", data, off + 34)[0]
        proto = struct.unpack_from("!B", data, off + 38)[0]

        flows.append(
            FlowRecord(
                ts=ts,
                src=_ipv4_from_u32(src_u32),
                dst=_ipv4_from_u32(dst_u32),
                src_port=int(src_port),
                dst_port=int(dst_port),
                proto=str(proto),
                latency_ms=0.0,
                bytes=int(doctets),
                packets=int(dpkts),
            )
        )

    return flows


def _decode_v9(data: bytes, exporter: str) -> List[FlowRecord]:
    """
    NetFlow v9 header is 20 bytes:
    version(2), count(2), sysUptime(4), unix_secs(4), seq(4), source_id(4)
    Followed by FlowSets.

    FlowSet IDs:
    0 template FlowSet
    1 options template FlowSet
    >255 data FlowSets, where FlowSet ID equals template ID  [oai_citation:10‡IETF](https://www.ietf.org/rfc/rfc3954.txt?utm_source=chatgpt.com)
    """
    if len(data) < 20:
        return []

    version, count = struct.unpack_from("!HH", data, 0)
    if version != 9:
        return []

    unix_secs = struct.unpack_from("!I", data, 8)[0]
    source_id = struct.unpack_from("!I", data, 16)[0]
    ts = float(unix_secs) if unix_secs else time.time()

    flows: List[FlowRecord] = []

    offset = 20
    while offset + 4 <= len(data):
        flowset_id, length = struct.unpack_from("!HH", data, offset)
        if length < 4:
            break
        end = offset + length
        if end > len(data):
            break

        body = data[offset + 4 : end]

        if flowset_id == 0:
            _parse_v9_template_flowset(body, exporter, source_id)
        elif flowset_id == 1:
            # Options templates not implemented in this starter version
            pass
        else:
            # Data FlowSet, flowset_id is template_id
            flows.extend(_parse_v9_data_flowset(body, exporter, source_id, flowset_id, ts))

        offset = end

    return flows


def _parse_v9_template_flowset(body: bytes, exporter: str, source_id: int) -> None:
    """
    Template FlowSet:
    sequence of template records:
      template_id(2), field_count(2), then field_count entries:
        field_type(2), field_length(2)  [oai_citation:11‡IETF](https://www.ietf.org/rfc/rfc3954.txt?utm_source=chatgpt.com)
    """
    off = 0
    while off + 4 <= len(body):
        template_id, field_count = struct.unpack_from("!HH", body, off)
        off += 4

        fields: List[_TemplateField] = []
        for _ in range(field_count):
            if off + 4 > len(body):
                return
            ftype, flen = struct.unpack_from("!HH", body, off)
            off += 4
            fields.append(_TemplateField(field_type=int(ftype), field_len=int(flen)))

        _V9_CACHE.put(exporter, source_id, _Template(template_id=int(template_id), fields=fields))

        # Template records are padded to 4 byte boundary within FlowSet, so continue as is.
        # Remaining bytes might be padding; loop will exit if not enough for a new template header.


def _parse_v9_data_flowset(
    body: bytes,
    exporter: str,
    source_id: int,
    template_id: int,
    ts: float,
) -> List[FlowRecord]:
    """
    Data FlowSet:
    sequence of data records, each matching template field lengths.
    Template must already be cached.  [oai_citation:12‡IETF](https://www.ietf.org/rfc/rfc3954.txt?utm_source=chatgpt.com)
    """
    tmpl = _V9_CACHE.get(exporter, source_id, template_id)
    if tmpl is None:
        return []

    record_len = sum(f.field_len for f in tmpl.fields)
    if record_len <= 0:
        return []

    flows: List[FlowRecord] = []
    off = 0

    while off + record_len <= len(body):
        rec = body[off : off + record_len]
        off += record_len

        parsed: Dict[str, int] = {}
        p = 0
        for f in tmpl.fields:
            vbytes = rec[p : p + f.field_len]
            p += f.field_len

            name = NFV9_FIELD.get(f.field_type)
            if not name:
                continue

            # Minimal decoding: common lengths are 1,2,4,8
            if f.field_len == 1:
                val = struct.unpack("!B", vbytes)[0]
            elif f.field_len == 2:
                val = struct.unpack("!H", vbytes)[0]
            elif f.field_len == 4:
                val = struct.unpack("!I", vbytes)[0]
            elif f.field_len == 8:
                val = struct.unpack("!Q", vbytes)[0]
            else:
                # For variable or uncommon sizes, skip for this starter
                continue

            parsed[name] = int(val)

        # Build FlowRecord if we have at least IPs
        if "src_ipv4" in parsed and "dst_ipv4" in parsed:
            flows.append(
                FlowRecord(
                    ts=ts,
                    src=_ipv4_from_u32(parsed["src_ipv4"]),
                    dst=_ipv4_from_u32(parsed["dst_ipv4"]),
                    src_port=int(parsed.get("src_port", 0)),
                    dst_port=int(parsed.get("dst_port", 0)),
                    proto=str(parsed.get("proto", 0)),
                    latency_ms=0.0,
                    bytes=int(parsed.get("bytes", 0)),
                    packets=int(parsed.get("packets", 0)),
                )
            )

    return flows
