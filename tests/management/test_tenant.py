import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import (
    MgmtV1,
    SSOSetupSuiteSettings,
    SSOSetupSuiteSettingsDisabledFeatures,
)

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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "enforceSSO": False,
                    "disabled": False,
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
            resp = client.mgmt.tenant.create(
                "name",
                "t1",
                ["domain.com"],
                {"k1": "v1"},
                enforce_sso=True,
                enforce_sso_exclusions=["user1", "user2"],
                federated_app_ids=["app1", "app2"],
                disabled=True,
            )
            self.assertEqual(resp["id"], "t1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "customAttributes": {"k1": "v1"},
                    "enforceSSO": True,
                    "enforceSSOExclusions": ["user1", "user2"],
                    "federatedAppIds": ["app1", "app2"],
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
                client.mgmt.tenant.update(
                    "t1", "new-name", ["domain.com"], enforce_sso=True, disabled=True
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "new-name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "enforceSSO": True,
                    "disabled": True,
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
                    "t1",
                    "new-name",
                    ["domain.com"],
                    {"k1": "v1"},
                    enforce_sso=True,
                    enforce_sso_exclusions=["user1", "user2"],
                    federated_app_ids=["app1", "app2"],
                    disabled=True,
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "new-name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "customAttributes": {"k1": "v1"},
                    "enforceSSO": True,
                    "enforceSSOExclusions": ["user1", "user2"],
                    "federatedAppIds": ["app1", "app2"],
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "t1"},
                allow_redirects=True,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                allow_redirects=True,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "tenantIds": ["id1"],
                    "tenantNames": ["name1"],
                    "tenantSelfProvisioningDomains": ["spd1"],
                    "customAttributes": {"k1": "v1"},
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_settings(self):
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
                client.mgmt.tenant.update_settings,
                "valid-id",
                {},
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.tenant.update_settings(
                    "t1",
                    self_provisioning_domains=["domain1.com"],
                    domains=["domain1.com", "domain2.com"],
                    auth_type="oidc",
                    session_settings_enabled=True,
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "tenantId": "t1",
                    "selfProvisioningDomains": ["domain1.com"],
                    "domains": ["domain1.com", "domain2.com"],
                    "authType": "oidc",
                    "enabled": True,
                },
                allow_redirects=False,
                params=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with SSO Setup Suite settings
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            sso_disabled_features = SSOSetupSuiteSettingsDisabledFeatures(
                saml=True, oidc=False, scim=True, sso_domains=False, group_mapping=True
            )
            sso_settings = SSOSetupSuiteSettings(
                enabled=True,
                style_id="style123",
                disabled_features=sso_disabled_features,
            )
            self.assertIsNone(
                client.mgmt.tenant.update_settings(
                    "t1",
                    self_provisioning_domains=["domain1.com"],
                    domains=["domain1.com", "domain2.com"],
                    auth_type="oidc",
                    session_settings_enabled=True,
                    sso_setup_suite_settings=sso_settings,
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "tenantId": "t1",
                    "selfProvisioningDomains": ["domain1.com"],
                    "domains": ["domain1.com", "domain2.com"],
                    "authType": "oidc",
                    "enabled": True,
                    "ssoSetupSuiteSettings": {
                        "enabled": True,
                        "styleId": "style123",
                        "disabledFeatures": {
                            "saml": True,
                            "oidc": False,
                            "scim": True,
                            "ssoDomains": False,
                            "groupMapping": True,
                        },
                    },
                },
                allow_redirects=False,
                params=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_settings(self):
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
                client.mgmt.tenant.load_settings,
                "valid-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {"domains": ["domain1.com", "domain2.com"], "authType": "oidc", "sessionSettingsEnabled": true}
                """
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.tenant.load_settings("t1")
            self.assertEqual(resp["domains"], ["domain1.com", "domain2.com"])
            self.assertEqual(resp["authType"], "oidc")
            self.assertEqual(resp["sessionSettingsEnabled"], True)
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "t1"},
                allow_redirects=True,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with SSO Setup Suite settings
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {
                    "domains": ["domain1.com", "domain2.com"],
                    "authType": "oidc",
                    "sessionSettingsEnabled": true,
                    "ssoSetupSuiteSettings": {
                        "enabled": true,
                        "styleId": "style123",
                        "disabledFeatures": {
                            "saml": true,
                            "oidc": false,
                            "scim": true,
                            "ssoDomains": false,
                            "groupMapping": true
                        }
                    }
                }
                """
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.tenant.load_settings("t1")
            self.assertEqual(resp["domains"], ["domain1.com", "domain2.com"])
            self.assertEqual(resp["authType"], "oidc")
            self.assertEqual(resp["sessionSettingsEnabled"], True)
            sso_settings = resp["ssoSetupSuiteSettings"]
            self.assertEqual(sso_settings["enabled"], True)
            self.assertEqual(sso_settings["styleId"], "style123")
            disabled_features = sso_settings["disabledFeatures"]
            self.assertEqual(disabled_features["saml"], True)
            self.assertEqual(disabled_features["oidc"], False)
            self.assertEqual(disabled_features["scim"], True)
            self.assertEqual(disabled_features["ssoDomains"], False)
            self.assertEqual(disabled_features["groupMapping"], True)
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "t1"},
                allow_redirects=True,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
