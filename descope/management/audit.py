from datetime import datetime
from typing import List

from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class Audit(AuthBase):
    def search(
        self,
        user_ids: List[str] = None,
        actions: List[str] = None,
        excluded_actions: List[str] = None,
        devices: List[str] = None,
        methods: List[str] = None,
        geos: List[str] = None,
        remote_addresses: List[str] = None,
        login_ids: List[str] = None,
        tenants: List[str] = None,
        no_tenants: bool = False,
        text: str = None,
        from_ts: datetime = None,
        to_ts: datetime = None,
    ) -> dict:
        """
        Search the audit trail up to last 30 days based on given parameters

        Args:
        user_ids (List[str]): Optional list of user IDs to filter by
        actions (List[str]): Optional list of actions to filter by
        excluded_actions (List[str]): Optional list of actions to exclude
        devices (List[str]): Optional list of devices to filter by. Current devices supported are "Bot"/"Mobile"/"Desktop"/"Tablet"/"Unknown"
        methods (List[str]): Optional list of methods to filter by. Current auth methods are "otp"/"totp"/"magiclink"/"oauth"/"saml"/"password"
        geos (List[str]): Optional list of geos to filter by. Geo is currently country code like "US", "IL", etc.
        remote_addresses (List[str]): Optional list of remote addresses to filter by
        login_ids (List[str]): Optional list of login IDs to filter by
        tenants (List[str]): Optional list of tenants to filter by
        no_tenants (bool): Should audits without any tenants always be included
        text (str): Free text search across all fields
        from_ts (datetime): Retrieve records newer than given time but not older than 30 days
        to_ts (datetime): Retrieve records older than given time

        Return value (dict):
        Return dict in the format
             {
                "audits": [
                    {
                        "projectId":"",
                        "userId": "",
                        "action": "",
                        "occurred": 0 (unix-time-milli),
                        "device": "",
                        "method": "",
                        "geo": "",
                        "remoteAddress": "",
                        "externalIds": [""],
                        "tenants": [""],
                        "data": {
                            "field1": "field1-value",
                            "more-details": "in-console-examples"
                        }
                    }
                ]
            }
        Raise:
        AuthException: raised if search operation fails
        """
        body = {"noTenants": no_tenants}
        if user_ids is not None:
            body["userIds"] = user_ids
        if actions is not None:
            body["actions"] = actions
        if excluded_actions is not None:
            body["excludedActions"] = excluded_actions
        if devices is not None:
            body["devices"] = devices
        if methods is not None:
            body["methods"] = methods
        if geos is not None:
            body["geos"] = geos
        if remote_addresses is not None:
            body["remoteAddresses"] = remote_addresses
        if login_ids is not None:
            body["externalIds"] = login_ids
        if tenants is not None:
            body["tenants"] = tenants
        if text is not None:
            body["text"] = text
        if from_ts is not None:
            body["from"] = from_ts.timestamp * 1000
        if to_ts is not None:
            body["to"] = to_ts.timestamp * 1000

        response = self._auth.do_post(
            MgmtV1.audit_search,
            body=body,
            pswd=self._auth.management_key,
        )
        return {
            "audits": list(map(Audit._convert_audit_record, response.json()["audits"]))
        }

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
