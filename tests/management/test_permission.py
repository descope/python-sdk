import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.future_utils import futu_await
from descope.management.common import MgmtV1

from tests.testutils import SSLMatcher, mock_http_call
from .. import common


class TestPermission(common.DescopeTest):
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

    async def test_create(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed flows
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.permission.create(
                        "name",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(client.mgmt.permission.create("P1", "Something"))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.permission_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "P1",
                    "description": "Something",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_update(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed flows
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.permission.update(
                        "name",
                        "new-name",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(
                    client.mgmt.permission.update(
                        "name",
                        "new-name",
                        "new-description",
                    )
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.permission_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "newName": "new-name",
                    "description": "new-description",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_delete(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed flows
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.permission.delete(
                        "name",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(await futu_await(client.mgmt.permission.delete("name")))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.permission_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_load_all(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed flows
        with mock_http_call(self.async_test, "get") as mock_get:
            mock_get.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.permission.load_all())

        # Test success flow
        with mock_http_call(self.async_test, "get") as mock_get:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = json.loads(
                """{"permissions": [{"name": "p1"}, {"name": "p2"}]}"""
            )
            mock_get.return_value = network_resp
            resp = await futu_await(client.mgmt.permission.load_all())
            permissions = resp["permissions"]
            self.assertEqual(len(permissions), 2)
            self.assertEqual(permissions[0]["name"], "p1")
            self.assertEqual(permissions[1]["name"], "p2")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.permission_load_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                follow_redirects=None,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
