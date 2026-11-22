"""Build and parse Windows event XML for the two event types this module uses.

All values written by the builders are synthetic. Host names use ".example", addresses use
RFC 5737 ranges, and user names are "user01" style. Nothing here is taken from a real log.

The builders produce the same XML shape that Windows writes to the event log for
Sysmon event 1 and Security event 4663, so the parser is tested against realistic raw text.
"""
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
COMPUTER = "ws-001.lab.example"

SYSMON1_FIELDS = (
    "UtcTime", "ProcessId", "Image", "OriginalFileName", "CommandLine", "User",
    "ParentProcessId", "ParentImage", "ParentCommandLine",
)
EVT4663_FIELDS = (
    "SubjectUserName", "SubjectDomainName", "ObjectServer", "ObjectType", "ObjectName",
    "AccessList", "AccessMask", "ProcessId", "ProcessName",
)


def _event(provider, event_id, channel, data_pairs):
    data = "".join(f'<Data Name="{k}">{escape(str(v))}</Data>' for k, v in data_pairs)
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        f"<Channel>{channel}</Channel><Computer>{COMPUTER}</Computer></System>"
        f"<EventData>{data}</EventData></Event>"
    )


def build_sysmon1(**fields):
    """Sysmon event 1 (process creation). Unknown field names are rejected."""
    bad = set(fields) - set(SYSMON1_FIELDS)
    if bad:
        raise ValueError(f"unknown Sysmon 1 fields: {sorted(bad)}")
    base = {
        "UtcTime": "2026-01-01 00:00:00.000", "ProcessId": "4242", "OriginalFileName": "-",
        "User": "LAB\\user01", "ParentProcessId": "1000", "ParentCommandLine": "-",
    }
    base.update(fields)
    return _event("Microsoft-Windows-Sysmon", 1, SYSMON_CHANNEL,
                  [(k, base[k]) for k in SYSMON1_FIELDS if k in base])


def build_security4663(event_id=4663, **fields):
    """Security event 4663 (object access). event_id is overridable to build a wrong-ID near-miss."""
    bad = set(fields) - set(EVT4663_FIELDS)
    if bad:
        raise ValueError(f"unknown 4663 fields: {sorted(bad)}")
    base = {
        "SubjectUserName": "user01", "SubjectDomainName": "LAB", "ObjectServer": "Security",
        "ObjectType": "File", "AccessList": "%%4416", "AccessMask": "0x1", "ProcessId": "0x1a4c",
    }
    base.update(fields)
    return _event("Microsoft-Windows-Security-Auditing", event_id, SECURITY_CHANNEL,
                  [(k, base[k]) for k in EVT4663_FIELDS if k in base])


def parse_event(raw):
    """Parse raw event XML into a flat dict of Sigma-style fields plus EventID and Channel."""
    root = ET.fromstring(raw)
    system = root.find(f"{NS}System")
    event = {
        "EventID": system.find(f"{NS}EventID").text,
        "Channel": system.find(f"{NS}Channel").text,
    }
    for item in root.find(f"{NS}EventData"):
        event[item.attrib["Name"]] = item.text or ""
    return event
