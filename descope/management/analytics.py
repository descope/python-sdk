from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class Analytics(HTTPBase):
    def search(
        self,
        actions: Optional[List[str]] = None,
        excluded_actions: Optional[List[str]] = None,
        from_ts: Optional[datetime] = None,
        to_ts: Optional[datetime] = None,
        devices: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        geos: Optional[List[str]] = None,
        tenants: Optional[List[str]] = None,
        group_by_action: bool = False,
        group_by_device: bool = False,
        group_by_method: bool = False,
        group_by_geo: bool = False,
        group_by_tenant: bool = False,
        group_by_referrer: bool = False,
        group_by_created: Optional[str] = None,
    ) -> dict:
        """
        Search analytics records according to given filters.

        Args:
        actions (List[str]): Optional list of actions to filter by.
        excluded_actions (List[str]): Optional list of actions to exclude.
        from_ts (datetime): Optional retrieve analytics newer than given time. Limited to no older than 12 months.
        to_ts (datetime): Optional retrieve records older than given time.
        devices (List[str]): Optional list of devices to filter by. Current devices supported are "Bot"/"Mobile"/"Desktop"/"Tablet"/"Unknown".
        methods (List[str]): Optional list of methods to filter by. Current auth methods are "otp"/"totp"/"magiclink"/"oauth"/"saml"/"password".
        geos (List[str]): Optional list of geos to filter by. Geo is currently country code like "US", "IL", etc.
        tenants (List[str]): Optional list of tenants to filter by.
        group_by_action (bool): Should we group summarized results by action.
        group_by_device (bool): Should we group summarized results by device.
        group_by_method (bool): Should we group summarized results by method.
        group_by_geo (bool): Should we group summarized results by geo.
        group_by_tenant (bool): Should we group summarized results by tenant.
        group_by_referrer (bool): Should we group summarized results by referrer.
        group_by_created (str): Optional how should we group the dates. Possible values are "h" for hour, "d" for day, "w" for week, "m" for month and "q" for quarter.

        Return value (dict):
        Return dict in the format {"analytics": [...]}
        "analytics" contains a list of analytic records matching the filters.

        Raise:
        AuthException: raised if search operation fails
        """
        body = {
            "actions": actions or [],
            "excludedActions": excluded_actions or [],
            "devices": devices or [],
            "methods": methods or [],
            "geos": geos or [],
            "tenants": tenants or [],
            "groupByAction": group_by_action,
            "groupByDevice": group_by_device,
            "groupByMethod": group_by_method,
            "groupByGeo": group_by_geo,
            "groupByTenant": group_by_tenant,
            "groupByReferrer": group_by_referrer,
        }
        if from_ts is not None:
            body["from"] = int(from_ts.timestamp() * 1000)
        if to_ts is not None:
            body["to"] = int(to_ts.timestamp() * 1000)
        if group_by_created is not None:
            body["groupByCreated"] = group_by_created

        response = self._http.post(
            MgmtV1.analytics_search_path,
            body=body,
        )
        return response.json()
