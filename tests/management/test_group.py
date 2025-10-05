from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from tests.testutils import SSLMatcher
from .. import common


class TestGroup(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.dummy_management_key = "key"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
            "kty": "EC",
            "use": "sig",
            "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
            "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
        }

    def test_load_all_groups(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.is_success = False
            self.assertRaises(
                AuthException,
                client.mgmt.group.load_all_groups,
                "tenant_id",
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNotNone(client.mgmt.group.load_all_groups("someTenantId"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.group_load_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_all_groups_for_members(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.is_success = False
            self.assertRaises(
                AuthException,
                client.mgmt.group.load_all_groups_for_members,
                "tenant_id",
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNotNone(
                client.mgmt.group.load_all_groups_for_members(
                    "someTenantId", ["one", "two"], ["three", "four"]
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.group_load_all_for_member_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                    "loginIds": ["three", "four"],
                    "userIds": ["one", "two"],
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_all_group_members(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.is_success = False
            self.assertRaises(
                AuthException,
                client.mgmt.group.load_all_group_members,
                "tenant_id",
                "group_id",
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNotNone(
                client.mgmt.group.load_all_group_members("someTenantId", "someGroupId")
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.group_load_all_group_members_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "someTenantId",
                    "groupId": "someGroupId",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
