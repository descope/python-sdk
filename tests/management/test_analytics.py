from datetime import datetime

import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestAnalytics:
    async def test_search(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.analytics.search())

        # Test success flow
        from_ts = datetime(2024, 1, 1, 0, 0, 0)
        to_ts = datetime(2024, 12, 31, 23, 59, 59)
        json_data = {
            "analytics": [
                {
                    "projectId": "P123",
                    "action": "login",
                    "created": "1704067200000",
                    "device": "Desktop",
                    "method": "otp",
                    "geo": "US",
                    "tenant": "tenant1",
                    "referrer": "https://example.com",
                    "cnt": "100",
                }
            ]
        }
        with client.mock_mgmt_post(make_response(json_data)) as mock_post:
            resp = await client.invoke(
                client.mgmt.analytics.search(
                    actions=["login"],
                    excluded_actions=["logout"],
                    from_ts=from_ts,
                    to_ts=to_ts,
                    devices=["Desktop"],
                    methods=["otp"],
                    geos=["US"],
                    tenants=["tenant1"],
                    group_by_action=True,
                    group_by_device=True,
                    group_by_method=True,
                    group_by_geo=True,
                    group_by_tenant=True,
                    group_by_referrer=True,
                    group_by_created="d",
                )
            )
            assert resp is not None
            assert "analytics" in resp
            assert len(resp["analytics"]) == 1
            assert resp["analytics"][0]["action"] == "login"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.analytics_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "actions": ["login"],
                    "excludedActions": ["logout"],
                    "from": int(from_ts.timestamp() * 1000),
                    "to": int(to_ts.timestamp() * 1000),
                    "devices": ["Desktop"],
                    "methods": ["otp"],
                    "geos": ["US"],
                    "tenants": ["tenant1"],
                    "groupByAction": True,
                    "groupByDevice": True,
                    "groupByMethod": True,
                    "groupByGeo": True,
                    "groupByTenant": True,
                    "groupByReferrer": True,
                    "groupByCreated": "d",
                },
                follow_redirects=False,
            )

    async def test_search_minimal(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow with minimal parameters
        json_data = {"analytics": []}
        with client.mock_mgmt_post(make_response(json_data)) as mock_post:
            resp = await client.invoke(client.mgmt.analytics.search())
            assert resp is not None
            assert "analytics" in resp
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.analytics_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "actions": [],
                    "excludedActions": [],
                    "devices": [],
                    "methods": [],
                    "geos": [],
                    "tenants": [],
                    "groupByAction": False,
                    "groupByDevice": False,
                    "groupByMethod": False,
                    "groupByGeo": False,
                    "groupByTenant": False,
                    "groupByReferrer": False,
                },
                follow_redirects=False,
            )
