import json
from unittest import mock
from unittest.mock import patch

from descope import AttributeMapping, AuthException, DescopeClient, RoleMapping
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1
from descope.management.sso_settings import (
    OIDCAttributeMapping,
    SSOOIDCSettings,
    SSOSAMLSettings,
    SSOSAMLSettingsByMetadata,
    SSOSettings,
)

from .. import common
from ..async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


class TestSSOSettings(common.DescopeTest):
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

    @parameterized_sync_async_subcase("delete_settings", "delete_settings_async")
    def test_delete_settings(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="delete", ok=False
        ) as mock_delete:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="delete", ok=True
        ) as mock_delete:
            MethodTestHelper.call_method(client.mgmt.sso, method_name, "tenant-id")

            HTTPMockHelper.assert_http_call(
                mock_delete,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                params={"tenantId": "tenant-id"},
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("load_settings", "load_settings_async")
    def test_load_settings(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
            )

        # Test success flow
        response_data = {
            "tenant": {
                "id": "T2AAAA",
                "name": "myTenantName",
                "selfProvisioningDomains": [],
                "customAttributes": {},
                "authType": "saml",
                "domains": ["lulu", "kuku"],
            },
            "saml": {
                "idpEntityId": "",
                "idpSSOUrl": "",
                "idpCertificate": "",
                "defaultSSORoles": ["aa", "bb"],
                "idpMetadataUrl": "https://dummy.com/metadata",
                "spEntityId": "",
                "spACSUrl": "",
                "spCertificate": "",
                "attributeMapping": {
                    "name": "name",
                    "email": "email",
                    "username": "",
                    "phoneNumber": "phone",
                    "group": "",
                    "givenName": "",
                    "middleName": "",
                    "familyName": "",
                    "picture": "",
                    "customAttributes": {},
                },
                "groupsMapping": [],
                "redirectUrl": "",
            },
            "oidc": {
                "name": "",
                "clientId": "",
                "clientSecret": "",
                "redirectUrl": "",
                "authUrl": "",
                "tokenUrl": "",
                "userDataUrl": "",
                "scope": [],
                "JWKsUrl": "",
                "userAttrMapping": {
                    "loginId": "sub",
                    "username": "",
                    "name": "name",
                    "email": "email",
                    "phoneNumber": "phone_number",
                    "verifiedEmail": "email_verified",
                    "verifiedPhone": "phone_number_verified",
                    "picture": "picture",
                    "givenName": "given_name",
                    "middleName": "middle_name",
                    "familyName": "family_name",
                },
                "manageProviderTokens": False,
                "callbackDomain": "",
                "prompt": [],
                "grantType": "authorization_code",
                "issuer": "",
            },
        }
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=True, json=lambda: response_data
        ) as mock_get:
            resp = MethodTestHelper.call_method(client.mgmt.sso, method_name, "T2AAAA")
            tenant = resp.get("tenant", {})
            self.assertEqual(tenant.get("id", ""), "T2AAAA")
            self.assertEqual(tenant.get("domains", []), ["lulu", "kuku"])
            saml_settings = resp.get("saml", {})
            self.assertEqual(
                saml_settings.get("idpMetadataUrl", ""), "https://dummy.com/metadata"
            )
            self.assertEqual(
                saml_settings.get("defaultSSORoles", ""),
                ["aa", "bb"],
            )
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_load_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"tenantId": "T2AAAA"},
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "configure_oidc_settings", "configure_oidc_settings_async"
    )
    def test_configure_oidc_settings(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
                SSOOIDCSettings(
                    name="myName",
                    client_id="cid",
                ),
                ["domain.com"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                SSOOIDCSettings(
                    name="myName",
                    client_id="cid",
                    client_secret="secret",
                    redirect_url="http://dummy.com/",
                    auth_url="http://dummy.com/auth",
                    token_url="http://dummy.com/token",
                    user_data_url="http://dummy.com/userInfo",
                    scope=["openid", "profile", "email"],
                    attribute_mapping=OIDCAttributeMapping(
                        login_id="my-id",
                        name="name",
                        given_name="givenName",
                        middle_name="middleName",
                        family_name="familyName",
                        email="email",
                        verified_email="verifiedEmail",
                        username="username",
                        phone_number="phoneNumber",
                        verified_phone="verifiedPhone",
                        picture="picture",
                    ),
                ),
                ["domain.com"],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_configure_oidc_settings}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "settings": {
                        "name": "myName",
                        "clientId": "cid",
                        "clientSecret": "secret",
                        "redirectUrl": "http://dummy.com/",
                        "authUrl": "http://dummy.com/auth",
                        "tokenUrl": "http://dummy.com/token",
                        "userDataUrl": "http://dummy.com/userInfo",
                        "scope": ["openid", "profile", "email"],
                        "JWKsUrl": None,
                        "manageProviderTokens": False,
                        "callbackDomain": None,
                        "prompt": None,
                        "grantType": None,
                        "issuer": None,
                        "userAttrMapping": {
                            "loginId": "my-id",
                            "name": "name",
                            "givenName": "givenName",
                            "middleName": "middleName",
                            "familyName": "familyName",
                            "email": "email",
                            "verifiedEmail": "verifiedEmail",
                            "username": "username",
                            "phoneNumber": "phoneNumber",
                            "verifiedPhone": "verifiedPhone",
                            "picture": "picture",
                        },
                    },
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "configure_saml_settings", "configure_saml_settings_async"
    )
    def test_configure_saml_settings(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
                SSOSAMLSettings(
                    idp_url="http://dummy.com",
                    idp_entity_id="ent1234",
                    idp_cert="cert",
                    sp_acs_url="http://spacsurl.com",
                    sp_entity_id="spentityid",
                    default_sso_roles=["aa", "bb"],
                ),
                "https://redirect.com",
                ["domain.com"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                SSOSAMLSettings(
                    idp_url="http://dummy.com",
                    idp_entity_id="ent1234",
                    idp_cert="cert",
                    attribute_mapping=AttributeMapping(
                        name="name",
                        given_name="givenName",
                        middle_name="middleName",
                        family_name="familyName",
                        picture="picture",
                        email="email",
                        phone_number="phoneNumber",
                        group="groups",
                    ),
                    role_mappings=[RoleMapping(groups=["grp1"], role_name="rl1")],
                    sp_acs_url="http://spacsurl.com",
                    sp_entity_id="spentityid",
                    default_sso_roles=["aa", "bb"],
                ),
                "https://redirect.com",
                ["domain.com"],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_configure_saml_settings}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "settings": {
                        "idpUrl": "http://dummy.com",
                        "entityId": "ent1234",
                        "idpCert": "cert",
                        "attributeMapping": {
                            "name": "name",
                            "givenName": "givenName",
                            "middleName": "middleName",
                            "familyName": "familyName",
                            "picture": "picture",
                            "email": "email",
                            "phoneNumber": "phoneNumber",
                            "group": "groups",
                            "customAttributes": None,
                        },
                        "roleMappings": [{"groups": ["grp1"], "roleName": "rl1"}],
                        "spACSUrl": "http://spacsurl.com",
                        "spEntityId": "spentityid",
                        "defaultSSORoles": ["aa", "bb"],
                    },
                    "redirectUrl": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "configure_saml_settings_by_metadata",
        "configure_saml_settings_by_metadata_async",
    )
    def test_configure_saml_settings_by_metadata(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
                SSOSAMLSettingsByMetadata(idp_metadata_url="http://dummy.com/metadata"),
                "https://redirect.com",
                ["domain.com"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                SSOSAMLSettingsByMetadata(
                    idp_metadata_url="http://dummy.com/metadata",
                    attribute_mapping=AttributeMapping(
                        name="name",
                        given_name="givenName",
                        middle_name="middleName",
                        family_name="familyName",
                        picture="picture",
                        email="email",
                        phone_number="phoneNumber",
                        group="groups",
                    ),
                    role_mappings=[RoleMapping(groups=["grp1"], role_name="rl1")],
                    sp_acs_url="http://spacsurl.com",
                    sp_entity_id="spentityid",
                    default_sso_roles=["aa", "bb"],
                ),
                "https://redirect.com",
                ["domain.com"],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_configure_saml_by_metadata_settings}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "settings": {
                        "idpMetadataUrl": "http://dummy.com/metadata",
                        "attributeMapping": {
                            "name": "name",
                            "givenName": "givenName",
                            "middleName": "middleName",
                            "familyName": "familyName",
                            "picture": "picture",
                            "email": "email",
                            "phoneNumber": "phoneNumber",
                            "group": "groups",
                            "customAttributes": None,
                        },
                        "roleMappings": [{"groups": ["grp1"], "roleName": "rl1"}],
                        "spACSUrl": "http://spacsurl.com",
                        "spEntityId": "spentityid",
                        "defaultSSORoles": ["aa", "bb"],
                    },
                    "redirectUrl": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_attribute_mapping_to_dict(self):
        self.assertRaises(ValueError, SSOSettings._attribute_mapping_to_dict, None)

    # Testing DEPRECATED functions
    @parameterized_sync_async_subcase("get_settings", "get_settings_async")
    def test_get_settings(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
            )

        # Test success flow
        response_data = {"domains": ["lulu", "kuku"], "tenantId": "tenant-id"}
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=True, json=lambda: response_data
        ) as mock_get:
            resp = MethodTestHelper.call_method(
                client.mgmt.sso, method_name, "tenant-id"
            )
            self.assertEqual(resp["tenantId"], "tenant-id")
            self.assertEqual(resp["domains"], ["lulu", "kuku"])
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"tenantId": "tenant-id"},
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("configure", "configure_async")
    def test_configure(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
                "https://idp.com",
                "entity-id",
                "cert",
                "https://redirect.com",
                ["domain.com"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                "https://idp.com",
                "entity-id",
                "cert",
                "https://redirect.com",
                ["domain.com"],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpURL": "https://idp.com",
                    "entityId": "entity-id",
                    "idpCert": "cert",
                    "redirectURL": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Domain is optional
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                "https://idp.com",
                "entity-id",
                "cert",
                "https://redirect.com",
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpURL": "https://idp.com",
                    "entityId": "entity-id",
                    "idpCert": "cert",
                    "redirectURL": "https://redirect.com",
                    "domains": None,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Redirect is optional
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                "https://idp.com",
                "entity-id",
                "cert",
                "",
                ["domain.com"],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpURL": "https://idp.com",
                    "entityId": "entity-id",
                    "idpCert": "cert",
                    "redirectURL": "",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "configure_via_metadata", "configure_via_metadata_async"
    )
    def test_configure_via_metadata(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
                "https://idp-meta.com",
                "https://redirect.com",
                ["domain.com"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                "https://idp-meta.com",
                "https://redirect.com",
                ["domain.com"],
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_metadata_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpMetadataURL": "https://idp-meta.com",
                    "redirectURL": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test partial arguments
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                "https://idp-meta.com",
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_metadata_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpMetadataURL": "https://idp-meta.com",
                    "redirectURL": None,
                    "domains": None,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("mapping", "mapping_async")
    def test_mapping(self, method_name, is_async):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                client.mgmt.sso,
                method_name,
                "tenant-id",
                [RoleMapping(["a", "b"], "role")],
                AttributeMapping(name="UName"),
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                client.mgmt.sso,
                method_name,
                "tenant-id",
                [RoleMapping(["a", "b"], "role")],
                AttributeMapping(name="UName"),
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_mapping_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "roleMappings": [{"groups": ["a", "b"], "roleName": "role"}],
                    "attributeMapping": {
                        "name": "UName",
                        "email": None,
                        "phoneNumber": None,
                        "group": None,
                        "givenName": None,
                        "middleName": None,
                        "familyName": None,
                        "picture": None,
                        "customAttributes": None,
                    },
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
