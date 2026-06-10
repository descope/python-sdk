from datetime import datetime

import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


@pytest.mark.asyncio
class TestAudit:
    async def test_search(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed search
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.audit.search("data"))

        # Test success search
        audit_resp = {
            "audits": [
                {
                    "projectId": "p",
                    "userId": "u1",
                    "action": "a1",
                    "externalIds": ["e1"],
                    "occurred": str(datetime.now().timestamp() * 1000),
                },
                {
                    "projectId": "p",
                    "userId": "u2",
                    "action": "a2",
                    "externalIds": ["e2"],
                    "occurred": str(datetime.now().timestamp() * 1000),
                },
            ]
        }
        with client.mock_mgmt_post(make_response(audit_resp)) as mock_post:
            resp = await client.invoke(client.mgmt.audit.search())
            audits = resp["audits"]
            assert len(audits) == 2
            assert audits[0]["loginIds"][0] == "e1"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.audit_search}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"noTenants": False},
                follow_redirects=False,
            )

    async def test_create_event(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed create_event
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.audit.create_event("a", "b", "c", "d"))

        # Test success create_event
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.audit.create_event(
                    action="pencil.created",
                    user_id="user-id",
                    actor_id="actor-id",
                    tenant_id="tenant-id",
                    type="info",
                    data={"some": "data"},
                )
            )
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.audit_create_event}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "action": "pencil.created",
                    "userId": "user-id",
                    "actorId": "actor-id",
                    "tenantId": "tenant-id",
                    "type": "info",
                    "data": {"some": "data"},
                },
                follow_redirects=False,
            )
