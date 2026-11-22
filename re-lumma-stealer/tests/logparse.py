"""Proxy log builder and a format dispatcher for the case files.

Proxy events are JSON objects with Sigma "proxy" category field names. All values are synthetic:
client addresses are RFC 5737 TEST-NET-1, hosts use ".example". A real proxy writes its own format;
this one only needs to carry the fields the rule reads (cs-method, c-useragent).
"""
import json

from winevent import parse_event

PROXY_FIELDS = ("c-ip", "cs-method", "cs-host", "cs-uri-stem", "c-useragent", "sc-status")


def build_proxy(**fields):
    """One proxy log record as a JSON line. Unknown field names are rejected."""
    bad = set(fields) - set(PROXY_FIELDS)
    if bad:
        raise ValueError(f"unknown proxy fields: {sorted(bad)}")
    base = {"c-ip": "192.0.2.10", "cs-method": "GET", "cs-host": "app.example", "cs-uri-stem": "/", "sc-status": "200"}
    base.update(fields)
    return json.dumps(base, sort_keys=True)


def parse_proxy(raw):
    event = json.loads(raw)
    event["LogType"] = "proxy"
    return event


PARSERS = {"windows_event_xml": parse_event, "proxy_json": parse_proxy}


def parse_any(log_format, raw):
    return PARSERS[log_format](raw)
