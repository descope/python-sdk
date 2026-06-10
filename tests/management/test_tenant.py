import pytest

from descope import AuthException
from descope.management.common import (
    MgmtV1,
    SSOSetupSuiteSettings,
    SSOSetupSuiteSettingsDisabledFeatures,
)

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT

MGMT_HEADERS = {
    **default_headers,
    "Authorization": f"Bearer {PROJECT_ID}:key",
    "x-descope-project-id": PROJECT_ID,
}


class TestTenant:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.create("valid-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"id": "t1"})) as mock_post:
            resp = await client.invoke(client.mgmt.tenant.create("name", "t1", ["domain.com"]))
            assert resp["id"] == "t1"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_create_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "name": "name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "enforceSSO": False,
                    "disabled": False,
                },
                follow_redirects=False,
            )

        # Test success flow with custom attributes, enforce_sso, disabled
        with client.mock_mgmt_post(make_response({"id": "t1"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.tenant.create(
                    "name",
                    "t1",
                    ["domain.com"],
                    {"k1": "v1"},
                    enforce_sso=True,
                    enforce_sso_exclusions=["user1", "user2"],
                    federated_app_ids=["app1", "app2"],
                    disabled=True,
                )
            )
            assert resp["id"] == "t1"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_create_path}",
                headers=MGMT_HEADERS,
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
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.update("valid-id", "valid-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.tenant.update("t1", "new-name", ["domain.com"], enforce_sso=True, disabled=True)
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "name": "new-name",
                    "id": "t1",
                    "selfProvisioningDomains": ["domain.com"],
                    "enforceSSO": True,
                    "disabled": True,
                },
                follow_redirects=False,
            )

        # Test success flow with custom attributes, enforce_sso, disabled
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
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
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_update_path}",
                headers=MGMT_HEADERS,
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
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.delete("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.tenant.delete("t1", True))
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_delete_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "t1", "cascade": True},
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.load("valid-id"))

        # Test success flow
        with client.mock_mgmt_get(
            make_response({"id": "t1", "name": "tenant1", "selfProvisioningDomains": ["domain1.com"], "createdTime": 172606520})
        ) as mock_get:
            resp = await client.invoke(client.mgmt.tenant.load("t1"))
            assert resp["name"] == "tenant1"
            assert resp["createdTime"] == 172606520
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_load_path}",
                headers=MGMT_HEADERS,
                params={"id": "t1"},
                follow_redirects=True,
            )

    async def test_load_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.load_all())

        # Test success flow
        with client.mock_mgmt_get(
            make_response({
                "tenants": [
                    {"id": "t1", "name": "tenant1", "selfProvisioningDomains": ["domain1.com"], "createdTime": 172606520},
                    {"id": "t2", "name": "tenant2", "selfProvisioningDomains": ["domain1.com"], "createdTime": 172606520},
                ]
            })
        ) as mock_get:
            resp = await client.invoke(client.mgmt.tenant.load_all())
            tenants = resp["tenants"]
            assert len(tenants) == 2
            assert tenants[0]["name"] == "tenant1"
            assert tenants[1]["name"] == "tenant2"
            assert tenants[0]["createdTime"] == 172606520
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_load_all_path}",
                headers=MGMT_HEADERS,
                params=None,
                follow_redirects=True,
            )

    async def test_search_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.search_all())

        # Test success flow
        with client.mock_mgmt_post(
            make_response({
                "tenants": [
                    {"id": "t1", "name": "tenant1", "selfProvisioningDomains": ["domain1.com"]},
                    {"id": "t2", "name": "tenant2", "selfProvisioningDomains": ["domain1.com"]},
                ]
            })
        ) as mock_post:
            resp = await client.invoke(
                client.mgmt.tenant.search_all(
                    ids=["id1"],
                    names=["name1"],
                    custom_attributes={"k1": "v1"},
                    self_provisioning_domains=["spd1"],
                )
            )
            tenants = resp["tenants"]
            assert len(tenants) == 2
            assert tenants[0]["name"] == "tenant1"
            assert tenants[1]["name"] == "tenant2"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_search_all_path}",
                headers=MGMT_HEADERS,
                json={
                    "tenantIds": ["id1"],
                    "tenantNames": ["name1"],
                    "tenantSelfProvisioningDomains": ["spd1"],
                    "customAttributes": {"k1": "v1"},
                },
                follow_redirects=False,
                params=None,
            )

    async def test_update_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.update_settings("valid-id", {}))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.tenant.update_settings(
                    "t1",
                    self_provisioning_domains=["domain1.com"],
                    domains=["domain1.com", "domain2.com"],
                    auth_type="oidc",
                    session_settings_enabled=True,
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers=MGMT_HEADERS,
                json={
                    "tenantId": "t1",
                    "selfProvisioningDomains": ["domain1.com"],
                    "domains": ["domain1.com", "domain2.com"],
                    "authType": "oidc",
                    "enabled": True,
                },
                follow_redirects=False,
                params=None,
            )

        # Test success flow with SSO Setup Suite settings
        with client.mock_mgmt_post(make_response()) as mock_post:
            sso_disabled_features = SSOSetupSuiteSettingsDisabledFeatures(
                saml=True, oidc=False, scim=True, sso_domains=False, group_mapping=True
            )
            sso_settings = SSOSetupSuiteSettings(
                enabled=True,
                style_id="style123",
                disabled_features=sso_disabled_features,
            )
            result = await client.invoke(
                client.mgmt.tenant.update_settings(
                    "t1",
                    self_provisioning_domains=["domain1.com"],
                    domains=["domain1.com", "domain2.com"],
                    auth_type="oidc",
                    session_settings_enabled=True,
                    sso_setup_suite_settings=sso_settings,
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers=MGMT_HEADERS,
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
                follow_redirects=False,
                params=None,
            )

    async def test_load_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.load_settings("valid-id"))

        # Test success flow
        with client.mock_mgmt_get(
            make_response({"domains": ["domain1.com", "domain2.com"], "authType": "oidc", "sessionSettingsEnabled": True})
        ) as mock_get:
            resp = await client.invoke(client.mgmt.tenant.load_settings("t1"))
            assert resp["domains"] == ["domain1.com", "domain2.com"]
            assert resp["authType"] == "oidc"
            assert resp["sessionSettingsEnabled"] is True
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers=MGMT_HEADERS,
                params={"id": "t1"},
                follow_redirects=True,
            )

    async def test_update_default_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.tenant.update_default_roles("valid-id", ["role1"]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.tenant.update_default_roles("t1", ["role1", "role2"]))
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_update_default_roles_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "t1", "defaultRoles": ["role1", "role2"]},
                follow_redirects=False,
            )

        # Test load_settings with SSO Setup Suite settings response
        with client.mock_mgmt_get(
            make_response({
                "domains": ["domain1.com", "domain2.com"],
                "authType": "oidc",
                "sessionSettingsEnabled": True,
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
            })
        ) as mock_get:
            resp = await client.invoke(client.mgmt.tenant.load_settings("t1"))
            assert resp["domains"] == ["domain1.com", "domain2.com"]
            assert resp["authType"] == "oidc"
            assert resp["sessionSettingsEnabled"] is True
            sso = resp["ssoSetupSuiteSettings"]
            assert sso["enabled"] is True
            assert sso["styleId"] == "style123"
            disabled = sso["disabledFeatures"]
            assert disabled["saml"] is True
            assert disabled["oidc"] is False
            assert disabled["scim"] is True
            assert disabled["ssoDomains"] is False
            assert disabled["groupMapping"] is True
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_settings_path}",
                headers=MGMT_HEADERS,
                params={"id": "t1"},
                follow_redirects=True,
            )

    async def test_generate_sso_configuration_link_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(
            make_response({"adminSSOConfigurationLink": "https://example.com/sso-config-link"})
        ) as mock_post:
            link = await client.invoke(client.mgmt.tenant.generate_sso_configuration_link("t1", 21600))
            assert link == "https://example.com/sso-config-link"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_generate_sso_configuration_link_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "tenantId": "t1",
                    "expireTime": 21600,
                },
                follow_redirects=False,
            )

    async def test_generate_sso_configuration_link_failed(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.tenant.generate_sso_configuration_link("t1", 21600)
                )

    async def test_generate_sso_configuration_link_with_all_params(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(
            make_response({"adminSSOConfigurationLink": "https://example.com/sso-config-link"})
        ) as mock_post:
            link = await client.invoke(
                client.mgmt.tenant.generate_sso_configuration_link(
                    tenant_id="t1",
                    expire_time=21600,
                    email="admin@example.com",
                    sso_id="sso123",
                )
            )
            assert link == "https://example.com/sso-config-link"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_generate_sso_configuration_link_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "tenantId": "t1",
                    "expireTime": 21600,
                    "email": "admin@example.com",
                    "ssoId": "sso123",
                },
                follow_redirects=False,
            )

    async def test_generate_sso_configuration_link_minimal_params(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(
            make_response({"adminSSOConfigurationLink": "https://example.com/sso-config-link"})
        ) as mock_post:
            link = await client.invoke(client.mgmt.tenant.generate_sso_configuration_link("t1"))
            assert link == "https://example.com/sso-config-link"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.tenant_generate_sso_configuration_link_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"tenantId": "t1"},
                follow_redirects=False,
            )
