# This is not part of the public API but a code helper
from __future__ import annotations

from datetime import datetime


class AuditBase:
    """Shared, I/O-free base for Audit management classes.

    Holds only static converters — no network I/O, no ``__init__``.
    The two concrete subclasses add the network layer:

    - ``Audit(AuditBase, HTTPBase)`` — sync
    - ``AuditAsync(AuditBase, AsyncHTTPBase)`` — async
    """

    @staticmethod
    def _convert_audit_record(a: dict) -> dict:
        return {
            "projectId": a.get("projectId", ""),
            "userId": a.get("userId", ""),
            "action": a.get("action", ""),
            "occurred": datetime.utcfromtimestamp(float(a.get("occurred", "0")) / 1000),
            "device": a.get("device", ""),
            "method": a.get("method", ""),
            "geo": a.get("geo", ""),
            "remoteAddress": a.get("remoteAddress", ""),
            "loginIds": a.get("externalIds", []),
            "tenants": a.get("tenants", []),
            "data": a.get("data", {}),
        }
