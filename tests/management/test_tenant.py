import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.management.common import MgmtV1

from .. import common


class TestTenant(common.DescopeTest):
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

    def test_create(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.tenant.create,
                "valid-name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"id": "t1"}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.tenant.create("name", "t1", ["domain.com"])
            self.assertEqual(resp["id"], "t1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "name": "name",
                        "id": "t1",
                        "selfProvisioningDomains": ["domain.com"],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_update(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.tenant.update,
                "valid-id",
                "valid-name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.tenant.update("t1", "new-name", ["domain.com"])
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "name": "new-name",
                        "id": "t1",
                        "selfProvisioningDomains": ["domain.com"],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_delete(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.tenant.delete,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.tenant.delete("t1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "id": "t1",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_load_all(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.tenant.load_all)

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {
                    "tenants": [
                        {"id": "t1", "name": "tenant1", "selfProvisioningDomains": ["domain1.com"]},
                        {"id": "t2", "name": "tenant2", "selfProvisioningDomains": ["domain1.com"]}
                    ]
                }
                """
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.tenant.load_all()
            tenants = resp["tenants"]
            self.assertEqual(len(tenants), 2)
            self.assertEqual(tenants[0]["name"], "tenant1")
            self.assertEqual(tenants[1]["name"], "tenant2")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_load_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                allow_redirects=None,
                verify=True,
            )
