from __future__ import annotations

import ipaddress
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from flow_agent_mcp.core.models import FlowRecord

# IPFIX protocol spec RFC 7011  [oai_citation:15‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc7011?utm_source=chatgpt.com)
# Information element IDs are maintained by IANA  [oai_citation:16‡IANA](https://www.iana.org/assignments/ipfix?utm_source=chatgpt.com)


def _ipv4_from_bytes(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


@dataclass
class _IPFIXField:
    ie_id: int
    length: int
    enterprise: Optional[int] = None


@dataclass
class _IPFIXTemplate:
    template_id: int
    fields: List[_IPFIXField]


class IPFIXTemplateCache:
    """
    IPFIX templates are scoped by exporter and observation domain id.
    RFC 7011 defines observation domain id in message header.  [oai_citation:17‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc7011?utm_source=chatgpt.com)
    """

    def __init__(self):
        self._templates: Dict[Tuple[str, int], Dict[int, _IPFIXTemplate]] = {}

    def put(self, exporter: str, obs_domain: int, template: _IPFIXTemplate) -> None:
        self._templates.setdefault((exporter, obs_domain), {})[template.template_id] = template

    def get(self, exporter: str, obs_domain: int, template_id: int) -> Optional[_IPFIXTemplate]:
        return self._templates.get((exporter, obs_domain), {}).get(template_id)


_IPFIX_CACHE = IPFIXTemplateCache()


# Common IPFIX information element IDs, from IANA registry  [oai_citation:18‡IANA](https://www.iana.org/assignments/ipfix?utm_source=chatgpt.com)
# We only implement a minimal subset needed for 5 tuple and counters.
IPFIX_IE = {
    8: "src_ipv4",      # sourceIPv4Address
    12: "dst_ipv4",     # destinationIPv4Address
    7: "src_port",      # sourceTransportPort
    11: "dst_port",     # destinationTransportPort
    4: "proto",         # protocolIdentifier
    1: "bytes",         # octetDeltaCount
    2: "packets",       # packetDeltaCount
}


def decode_ipfix(data: bytes, exporter: str = "unknown") -> List[FlowRecord]:
    """
    Decode IPFIX message into FlowRecord list.

    exporter
      Should be the sender IP address string for template cache key.

    Structure:
      Message header 16 bytes, then sets.
      Set header 4 bytes: set_id, length.
      Template set id = 2, Options template set id = 3, Data set id >= 256
    RFC 7011  [oai_citation:19‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc7011?utm_source=chatgpt.com)
    """
    if len(data) < 16:
        return []

    version = struct.unpack_from("!H", data, 0)[0]
    if version != 10:
        return []

    length = struct.unpack_from("!H", data, 2)[0]
    export_time = struct.unpack_from("!I", data, 4)[0]
    obs_domain = struct.unpack_from("!I", data, 12)[0]

    ts = float(export_time) if export_time else time.time()

    # Guard length
    msg = data[: min(len(data), length)] if length >= 16 else data

    flows: List[FlowRecord] = []
    offset = 16

    while offset + 4 <= len(msg):
        set_id, set_len = struct.unpack_from("!HH", msg, offset)
        if set_len < 4:
            break
        end = offset + set_len
        if end > len(msg):
            break

        body = msg[offset + 4 : end]

        if set_id == 2:
            _parse_ipfix_template_set(body, exporter, obs_domain)
        elif set_id == 3:
            # Options templates not implemented in this starter
            pass
        elif set_id >= 256:
            flows.extend(_parse_ipfix_data_set(body, exporter, obs_domain, set_id, ts))

        offset = end

    return flows


def _parse_ipfix_template_set(body: bytes, exporter: str, obs_domain: int) -> None:
    """
    Template record format:
      template_id(2), field_count(2), then field specifiers.

    Field specifier:
      ie_id(2), field_length(2)
      if enterprise bit is set on ie_id, then enterprise number (4) follows.

    RFC 7011  [oai_citation:20‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc7011?utm_source=chatgpt.com)
    """
    off = 0
    while off + 4 <= len(body):
        template_id, field_count = struct.unpack_from("!HH", body, off)
        off += 4

        fields: List[_IPFIXField] = []
        for _ in range(field_count):
            if off + 4 > len(body):
                return

            raw_ie, flen = struct.unpack_from("!HH", body, off)
            off += 4

            enterprise = None
            ie_id = raw_ie

            # Enterprise bit is the highest bit of the IE ID field
            if raw_ie & 0x8000:
                ie_id = raw_ie & 0x7FFF
                if off + 4 > len(body):
                    return
                enterprise = struct.unpack_from("!I", body, off)[0]
                off += 4

            fields.append(_IPFIXField(ie_id=int(ie_id), length=int(flen), enterprise=enterprise))

        _IPFIX_CACHE.put(exporter, obs_domain, _IPFIXTemplate(template_id=int(template_id), fields=fields))

        # Padding may exist. The loop will exit if not enough bytes remain.


def _parse_ipfix_data_set(
    body: bytes,
    exporter: str,
    obs_domain: int,
    template_id: int,
    ts: float,
) -> List[FlowRecord]:
    tmpl = _IPFIX_CACHE.get(exporter, obs_domain, template_id)
    if tmpl is None:
        return []

    record_len = sum(f.length for f in tmpl.fields)
    if record_len <= 0:
        return []

    flows: List[FlowRecord] = []
    off = 0

    while off + record_len <= len(body):
        rec = body[off : off + record_len]
        off += record_len

        parsed: Dict[str, object] = {}
        p = 0
        for f in tmpl.fields:
            vbytes = rec[p : p + f.length]
            p += f.length

            name = IPFIX_IE.get(f.ie_id)
            if not name:
                continue

            if name in ("src_ipv4", "dst_ipv4") and f.length == 4:
                parsed[name] = _ipv4_from_bytes(vbytes)
                continue

            # Minimal int decoding for common fixed lengths
            if f.length == 1:
                parsed[name] = int(struct.unpack("!B", vbytes)[0])
            elif f.length == 2:
                parsed[name] = int(struct.unpack("!H", vbytes)[0])
            elif f.length == 4:
                parsed[name] = int(struct.unpack("!I", vbytes)[0])
            elif f.length == 8:
                parsed[name] = int(struct.unpack("!Q", vbytes)[0])

        if "src_ipv4" in parsed and "dst_ipv4" in parsed:
            flows.append(
                FlowRecord(
                    ts=ts,
                    src=str(parsed["src_ipv4"]),
                    dst=str(parsed["dst_ipv4"]),
                    src_port=int(parsed.get("src_port", 0)),
                    dst_port=int(parsed.get("dst_port", 0)),
                    proto=str(parsed.get("proto", 0)),
                    latency_ms=0.0,
                    bytes=int(parsed.get("bytes", 0)),
                    packets=int(parsed.get("packets", 0)),
                )
            )

    return flows
