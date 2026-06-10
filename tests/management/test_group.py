import pytest

from descope import AuthException
from descope.management.common import MgmtV1

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT


class TestGroup:
    async def test_load_all_groups(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.group.load_all_groups("tenant_id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            assert await client.invoke(client.mgmt.group.load_all_groups("someTenantId")) is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.group_load_all_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                },
                follow_redirects=False,
            )

    async def test_load_all_groups_for_members(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.group.load_all_groups_for_members("tenant_id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            assert (
                await client.invoke(
                    client.mgmt.group.load_all_groups_for_members("someTenantId", ["one", "two"], ["three", "four"])
                )
                is not None
            )
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.group_load_all_for_member_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                    "loginIds": ["three", "four"],
                    "userIds": ["one", "two"],
                },
                follow_redirects=False,
            )

    async def test_load_all_group_members(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.group.load_all_group_members("tenant_id", "group_id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            assert (
                await client.invoke(client.mgmt.group.load_all_group_members("someTenantId", "someGroupId"))
                is not None
            )
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.group_load_all_group_members_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                    "groupId": "someGroupId",
                },
                follow_redirects=False,
            )
