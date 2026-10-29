from __future__ import annotations

import re
from dataclasses import dataclass


_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_TS_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)
_TAG_RE = re.compile(r"^(?P<tag>[A-Za-z0-9_./-]+)(?:\[(?P<pid>\d+)\])?:?")


@dataclass
class SyslogMessage:
    """Parsed RFC 3164 syslog message.

    Fields:
        priority: raw PRI value (facility*8 + severity)
        facility: facility number (0..23)
        severity: severity number (0..7)
        timestamp: the original timestamp string, verbatim
        hostname: the hostname field, or empty string if absent
        tag: the program tag (without the optional [pid])
        message: the body text after the tag
    """

    priority: int
    facility: int
    severity: int
    timestamp: str
    hostname: str
    tag: str
    message: str


def parse(raw: str) -> SyslogMessage:
    """Parse a single RFC 3164 syslog datagram string.

    Raises ValueError on malformed input (missing PRI, out-of-range priority,
    or a HEADER section whose timestamp does not match the BSD format).
    """
    text = raw.rstrip("\r\n")
    m = _PRI_RE.match(text)
    if m is None:
        raise ValueError("missing or malformed PRI")

    pri = int(m.group("pri"))
    if pri > 191:
        raise ValueError("priority out of range")

    facility = pri >> 3
    severity = pri & 0x07
    rest = text[m.end():]

    ts_match = _TS_RE.match(rest)
    if ts_match is None:
        raise ValueError("invalid timestamp")
    if ts_match.group("month") not in _MONTHS:
        raise ValueError("invalid month")
    day = int(ts_match.group("day"))
    if not (1 <= day <= 31):
        raise ValueError("invalid day")

    timestamp = ts_match.group(0)
    rest = rest[ts_match.end():].lstrip(" ")

    # HOSTNAME is optional in RFC 3164. If present, it ends at the first space.
    hostname = ""
    space = rest.find(" ")
    if space == -1:
        raise ValueError("missing TAG and MSG")
    hostname = rest[:space]
    rest = rest[space + 1:]

    tag_match = _TAG_RE.match(rest)
    if tag_match is None:
        tag = ""
        message = rest
    else:
        tag = tag_match.group("tag")
        message = rest[tag_match.end():].lstrip(" ")

    return SyslogMessage(
        priority=pri,
        facility=facility,
        severity=severity,
        timestamp=timestamp,
        hostname=hostname,
        tag=tag,
        message=message,
    )
