import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
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
                json={
                    "name": "name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with custom attributes, enforce_sso, disabled
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"id": "t1"}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.tenant.create("name", "t1", ["domain.com"], {"k1": "v1"}, enforce_sso=True, disabled=True)
            self.assertEqual(resp["id"], "t1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "name": "name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "customAttributes": {"k1": "v1"},
                    "enforceSSO": True,
                    "disabled": True,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "name": "new-name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with custom attributes, enforce_sso, disabled
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.tenant.update(
                    "t1", "new-name", ["domain.com"], {"k1": "v1"}, enforce_sso=True, disabled=True
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "name": "new-name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "customAttributes": {"k1": "v1"},
                     "enforceSSO": True,
                    "disabled": True,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
            self.assertIsNone(client.mgmt.tenant.delete("t1", True))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"id": "t1", "cascade": True},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.tenant.load,
                "valid-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {"id": "t1", "name": "tenant1", "selfProvisioningDomains": ["domain1.com"], "createdTime": 172606520}
                """
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.tenant.load("t1")
            self.assertEqual(resp["name"], "tenant1")
            self.assertEqual(resp["createdTime"], 172606520)
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"id": "t1"},
                allow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                        {"id": "t1", "name": "tenant1", "selfProvisioningDomains": ["domain1.com"], "createdTime": 172606520},
                        {"id": "t2", "name": "tenant2", "selfProvisioningDomains": ["domain1.com"], "createdTime": 172606520}
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
            self.assertEqual(tenants[0]["createdTime"], 172606520)
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_load_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                allow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_search_all(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.tenant.search_all)

        # Test success flow
        with patch("requests.post") as mock_post:
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
            mock_post.return_value = network_resp
            resp = client.mgmt.tenant.search_all(
                ids=["id1"],
                names=["name1"],
                custom_attributes={"k1": "v1"},
                self_provisioning_domains=["spd1"],
                enforce_sso=True
            )
            tenants = resp["tenants"]
            self.assertEqual(len(tenants), 2)
            self.assertEqual(tenants[0]["name"], "tenant1")
            self.assertEqual(tenants[1]["name"], "tenant2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_search_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                json={
                    "tenantIds": ["id1"],
                    "tenantNames": ["name1"],
                    "tenantSelfProvisioningDomains": ["spd1"],
                    "customAttributes": {"k1": "v1"},
                    "enforceSSO": True,
                    "disabled": None
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
