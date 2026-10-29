# bsd_syslog_message_utils

Parses RFC 3164 syslog datagrams into priority, facility, severity, timestamp, hostname, tag, and message fields.

```python
from bsd_syslog_message_utils import parse

msg = parse("<34>Oct 11 22:14:15 mymachine su: 'su root' failed")
print(msg.priority)   # 34
print(msg.facility)    # 4
print(msg.severity)    # 2
print(msg.timestamp)  # Oct 11 22:14:15
print(msg.hostname)   # mymachine
print(msg.tag)         # su
print(msg.message)     # 'su root' failed
```

## Why this exists

Syslog on BSD-derived systems sends single-line UDP datagrams in the RFC 3164 format. That format is old and inconsistent across senders, but a handful of fields are stable enough to parse structurally: the angle-bracketed PRI, the BSD-format timestamp ("Oct 11 22:14:15"), a hostname, and a TAG-MSG pair.

This library parses only those structural fields and stops there. It does not attempt to interpret the content of the message body, correlate log streams, or normalise timestamps into UTC — those concerns belong to a downstream consumer with more context than a single datagram can provide.

## Edge cases

The TAG field is the program name, optionally followed by `[pid]` before a colon. When the colon is absent or the TAG doesn't match the expected pattern, the library sets tag to an empty string and treats the entire remainder as the message, rather than guessing. Single-digit days in the timestamp ("Oct  1") are preserved as-is; the timestamp is returned verbatim, not converted to a `datetime`, because RFC 3164 timestamps carry no year or timezone and any conversion would impose an assumption the datagram does not support.
