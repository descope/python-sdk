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

    def test_delete_settings(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.delete") as mock_delete:
            mock_delete.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.sso.delete_settings,
                "tenant-id",
            )

        # Test success flow
        with patch("requests.delete") as mock_delete:
            network_resp = mock.Mock()
            network_resp.ok = True

            mock_delete.return_value = network_resp
            client.mgmt.sso.delete_settings("tenant-id")

            mock_delete.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                params={"tenantId": "tenant-id"},
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                allow_redirects=False,
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
                client.mgmt.sso.load_settings,
                "tenant-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"tenant": {"id": "T2AAAA", "name": "myTenantName", "selfProvisioningDomains": [], "customAttributes": {}, "authType": "saml", "domains": ["lulu", "kuku"]}, "saml": {"idpEntityId": "", "idpSSOUrl": "", "idpCertificate": "", "idpAdditionalCertificates": ["cert1", "cert2"], "defaultSSORoles": ["aa", "bb"], "idpMetadataUrl": "https://dummy.com/metadata", "spEntityId": "", "spACSUrl": "", "spCertificate": "", "attributeMapping": {"name": "name", "email": "email", "username": "", "phoneNumber": "phone", "group": "", "givenName": "", "middleName": "", "familyName": "", "picture": "", "customAttributes": {}}, "groupsMapping": [], "redirectUrl": ""}, "oidc": {"name": "", "clientId": "", "clientSecret": "", "redirectUrl": "", "authUrl": "", "tokenUrl": "", "userDataUrl": "", "scope": [], "JWKsUrl": "", "userAttrMapping": {"loginId": "sub", "username": "", "name": "name", "email": "email", "phoneNumber": "phone_number", "verifiedEmail": "email_verified", "verifiedPhone": "phone_number_verified", "picture": "picture", "givenName": "given_name", "middleName": "middle_name", "familyName": "family_name"}, "manageProviderTokens": false, "callbackDomain": "", "prompt": [], "grantType": "authorization_code", "issuer": ""}}"""
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.sso.load_settings("T2AAAA")
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
            self.assertEqual(
                saml_settings.get("idpAdditionalCertificates", []),
                ["cert1", "cert2"],
            )
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_load_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"tenantId": "T2AAAA"},
                allow_redirects=True,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure_oidc_settings(self):
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
                client.mgmt.sso.configure_oidc_settings,
                "tenant-id",
                SSOOIDCSettings(
                    name="myName",
                    client_id="cid",
                ),
                ["domain.com"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure_oidc_settings(
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
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure_saml_settings(self):
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
                client.mgmt.sso.configure_saml_settings,
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
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure_saml_settings(
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
            )
            mock_post.assert_called_with(
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
                        "idpAdditionalCerts": None,
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure_saml_settings_by_metadata(self):
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
                client.mgmt.sso.configure_saml_settings_by_metadata,
                "tenant-id",
                SSOSAMLSettingsByMetadata(idp_metadata_url="http://dummy.com/metadata"),
                "https://redirect.com",
                ["domain.com"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure_saml_settings_by_metadata(
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
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure_saml_settings_with_additional_certs(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test success flow with additional certs
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure_saml_settings(
                    "tenant-id",
                    SSOSAMLSettings(
                        idp_url="http://dummy.com",
                        idp_entity_id="ent1234",
                        idp_cert="cert",
                        idp_additional_certs=["cert1", "cert2", "cert3"],
                        attribute_mapping=AttributeMapping(
                            name="name",
                            email="email",
                        ),
                        role_mappings=[RoleMapping(groups=["grp1"], role_name="rl1")],
                        default_sso_roles=["aa", "bb"],
                    ),
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            mock_post.assert_called_with(
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
                        "idpAdditionalCerts": ["cert1", "cert2", "cert3"],
                        "attributeMapping": {
                            "name": "name",
                            "email": "email",
                            "phoneNumber": None,
                            "group": None,
                            "givenName": None,
                            "middleName": None,
                            "familyName": None,
                            "picture": None,
                            "customAttributes": None,
                        },
                        "roleMappings": [{"groups": ["grp1"], "roleName": "rl1"}],
                        "spACSUrl": None,
                        "spEntityId": None,
                        "defaultSSORoles": ["aa", "bb"],
                    },
                    "redirectUrl": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_attribute_mapping_to_dict(self):
        self.assertRaises(ValueError, SSOSettings._attribute_mapping_to_dict, None)

    # Testing DEPRECATED functions
    def test_get_settings(self):
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
                client.mgmt.sso.get_settings,
                "tenant-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"domains": ["lulu", "kuku"], "tenantId": "tenant-id"}"""
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.sso.get_settings("tenant-id")
            self.assertEqual(resp["tenantId"], "tenant-id")
            self.assertEqual(resp["domains"], ["lulu", "kuku"])
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"tenantId": "tenant-id"},
                allow_redirects=True,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure(self):
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
                client.mgmt.sso.configure,
                "tenant-id",
                "https://idp.com",
                "entity-id",
                "cert",
                "https://redirect.com",
                ["domain.com"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Domain is optional
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "https://redirect.com",
                )
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Redirect is optional
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "",
                    ["domain.com"],
                )
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure_via_metadata(self):
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
                client.mgmt.sso.configure_via_metadata,
                "tenant-id",
                "https://idp-meta.com",
                "https://redirect.com",
                ["domain.com"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure_via_metadata(
                    "tenant-id",
                    "https://idp-meta.com",
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test partial arguments
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure_via_metadata(
                    "tenant-id",
                    "https://idp-meta.com",
                )
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_mapping(self):
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
                client.mgmt.sso.mapping,
                "tenant-id",
                [RoleMapping(["a", "b"], "role")],
                AttributeMapping(name="UName"),
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.mapping(
                    "tenant-id",
                    [RoleMapping(["a", "b"], "role")],
                    AttributeMapping(name="UName"),
                )
            )
            mock_post.assert_called_with(
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
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
