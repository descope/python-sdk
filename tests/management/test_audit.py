from datetime import datetime
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.future_utils import futu_await
from descope.management.common import MgmtV1

from tests.testutils import SSLMatcher, mock_http_call
from .. import common


class TestAudit(common.DescopeTest):
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

    async def test_search(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed search
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.audit.search(
                        "data",
                    )
                )

        # Test success search
        with mock_http_call(self.async_test, "post") as mock_post:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = {
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
            mock_post.return_value = network_resp
            resp = await futu_await(client.mgmt.audit.search())
            audits = resp["audits"]
            self.assertEqual(len(audits), 2)
            self.assertEqual(audits[0]["loginIds"][0], "e1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_search}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"noTenants": False},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_create_event(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed search
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.audit.create_event("a", "b", "c", "d"))

        # Test success search
        with mock_http_call(self.async_test, "post") as mock_post:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = {}
            mock_post.return_value = network_resp
            await futu_await(
                client.mgmt.audit.create_event(
                    action="pencil.created",
                    user_id="user-id",
                    actor_id="actor-id",
                    tenant_id="tenant-id",
                    type="info",
                    data={"some": "data"},
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.audit_create_event}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
