import json
from unittest import mock
from unittest.mock import patch

from descope import (
    AuthException,
    DescopeClient,
    SAMLIDPAttributeMappingInfo,
    SAMLIDPGroupsMappingInfo,
    SAMLIDPRoleGroupMappingInfo,
)
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.future_utils import futu_await
from descope.management.common import MgmtV1

from tests.testutils import SSLMatcher, mock_http_call
from .. import common


class TestSSOApplication(common.DescopeTest):
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

    async def test_create_oidc_application(self):
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
                    client.mgmt.sso_application.create_oidc_application(
                        "valid-name",
                        "http://dummy.com",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = json.loads("""{"id": "app1"}""")
            mock_post.return_value = network_resp
            resp = await futu_await(
                client.mgmt.sso_application.create_oidc_application(
                    name="name",
                    login_page_url="http://dummy.com",
                    force_authentication=True,
                )
            )
            self.assertEqual(resp["id"], "app1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_application_oidc_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "loginPageUrl": "http://dummy.com",
                    "enabled": True,
                    "id": None,
                    "description": None,
                    "logo": None,
                    "forceAuthentication": True,
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_create_saml_application(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed flows
        with self.assertRaises(Exception):
            await futu_await(
                client.mgmt.sso_application.create_saml_application(
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=True,
                    metadata_url="",
                )
            )

        with self.assertRaises(Exception):

            await futu_await(
                client.mgmt.sso_application.create_saml_application(
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=False,
                    entity_id="",
                )
            )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.sso_application.create_saml_application(
                        name="valid-name",
                        login_page_url="http://dummy.com",
                        use_metadata_info=True,
                        metadata_url="http://dummy.com/md",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = json.loads("""{"id": "app1"}""")
            mock_post.return_value = network_resp
            resp = await futu_await(
                client.mgmt.sso_application.create_saml_application(
                    name="name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=True,
                    metadata_url="http://dummy.com/md",
                    attribute_mapping=[
                        SAMLIDPAttributeMappingInfo("name1", "type1", "val1")
                    ],
                    groups_mapping=[
                        SAMLIDPGroupsMappingInfo(
                            "name1",
                            "type1",
                            "roles",
                            "val1",
                            [SAMLIDPRoleGroupMappingInfo("id1", "name1")],
                        )
                    ],
                    subject_name_id_type="email",
                    default_relay_state="relayState",
                    force_authentication=True,
                    logout_redirect_url="http://dummy.com/logout",
                )
            )
            self.assertEqual(resp["id"], "app1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_application_saml_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "loginPageUrl": "http://dummy.com",
                    "enabled": True,
                    "id": None,
                    "description": None,
                    "logo": None,
                    "useMetadataInfo": True,
                    "metadataUrl": "http://dummy.com/md",
                    "entityId": None,
                    "acsUrl": None,
                    "certificate": None,
                    "attributeMapping": [
                        {"name": "name1", "type": "type1", "value": "val1"}
                    ],
                    "groupsMapping": [
                        {
                            "name": "name1",
                            "type": "type1",
                            "filterType": "roles",
                            "value": "val1",
                            "roles": [{"id": "id1", "name": "name1"}],
                        }
                    ],
                    "acsAllowedCallbacks": [],
                    "subjectNameIdType": "email",
                    "subjectNameIdFormat": None,
                    "defaultRelayState": "relayState",
                    "forceAuthentication": True,
                    "logoutRedirectUrl": "http://dummy.com/logout",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_update_oidc_application(self):
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
                    client.mgmt.sso_application.update_oidc_application(
                        "id1",
                        "valid-name",
                        "http://dummy.com",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            network_resp = mock.Mock()
            network_resp.is_success = True
            self.assertIsNone(
                await futu_await(
                    client.mgmt.sso_application.update_oidc_application(
                        "app1", "name", "http://dummy.com"
                    )
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_application_oidc_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "app1",
                    "name": "name",
                    "loginPageUrl": "http://dummy.com",
                    "enabled": True,
                    "description": None,
                    "logo": None,
                    "forceAuthentication": False,
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_update_saml_application(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed flows
        with self.assertRaises(Exception):
            await futu_await(
                client.mgmt.sso_application.update_saml_application(
                    id="id1",
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=True,
                    metadata_url="",
                )
            )

        with self.assertRaises(Exception):

            await futu_await(
                client.mgmt.sso_application.update_saml_application(
                    id="id1",
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=False,
                    entity_id="",
                )
            )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.sso_application.update_saml_application(
                        id="id1",
                        name="valid-name",
                        login_page_url="http://dummy.com",
                        use_metadata_info=True,
                        metadata_url="http://dummy.com/md",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            network_resp = mock.Mock()
            network_resp.is_success = True
            self.assertIsNone(
                await futu_await(
                    client.mgmt.sso_application.update_saml_application(
                        id="id1",
                        name="name",
                        login_page_url="http://dummy.com",
                        use_metadata_info=False,
                        metadata_url="",
                        entity_id="ent1234",
                        acs_url="http://dummy.com/acs",
                        certificate="cert",
                        attribute_mapping=[
                            SAMLIDPAttributeMappingInfo("name1", "type1", "val1")
                        ],
                        groups_mapping=[
                            SAMLIDPGroupsMappingInfo(
                                "name1",
                                "type1",
                                "roles",
                                "val1",
                                [SAMLIDPRoleGroupMappingInfo("id1", "name1")],
                            )
                        ],
                        subject_name_id_type="",
                    )
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_application_saml_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "loginPageUrl": "http://dummy.com",
                    "enabled": True,
                    "id": "id1",
                    "description": None,
                    "logo": None,
                    "useMetadataInfo": False,
                    "metadataUrl": "",
                    "entityId": "ent1234",
                    "acsUrl": "http://dummy.com/acs",
                    "certificate": "cert",
                    "attributeMapping": [
                        {"name": "name1", "type": "type1", "value": "val1"}
                    ],
                    "groupsMapping": [
                        {
                            "name": "name1",
                            "type": "type1",
                            "filterType": "roles",
                            "value": "val1",
                            "roles": [{"id": "id1", "name": "name1"}],
                        }
                    ],
                    "acsAllowedCallbacks": [],
                    "subjectNameIdType": "",
                    "subjectNameIdFormat": None,
                    "defaultRelayState": None,
                    "forceAuthentication": False,
                    "logoutRedirectUrl": None,
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
                    client.mgmt.sso_application.delete(
                        "valid-id",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(client.mgmt.sso_application.delete("app1"))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_application_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "app1",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_load(self):
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
                await futu_await(
                    client.mgmt.sso_application.load(
                        "valid-id",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "get") as mock_get:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = json.loads(
                """
                {"id":"app1","name":"App1","description":"","enabled":true,"logo":"","appType":"saml","samlSettings":{"loginPageUrl":"http://dummy.com/login","idpCert":"cert","useMetadataInfo":true,"metadataUrl":"http://dummy.com/md","entityId":"","acsUrl":"","certificate":"","attributeMapping":[{"name":"email","type":"","value":"attrVal1"}],"groupsMapping":[{"name":"grp1","type":"","filterType":"roles","value":"","roles":[{"id":"myRoleId","name":"myRole"}]}],"idpMetadataUrl":"","idpEntityId":"","idpSsoUrl":"","acsAllowedCallbacks":[],"subjectNameIdType":"","subjectNameIdFormat":""},"oidcSettings":{"loginPageUrl":"","issuer":"","discoveryUrl":""}}
                """
            )
            mock_get.return_value = network_resp
            resp = await futu_await(client.mgmt.sso_application.load("app1"))
            self.assertEqual(resp["name"], "App1")
            self.assertEqual(resp["appType"], "saml")
            self.assertEqual(
                resp["samlSettings"]["loginPageUrl"], "http://dummy.com/login"
            )
            self.assertEqual(resp["samlSettings"]["useMetadataInfo"], True)
            self.assertEqual(resp["samlSettings"]["metadataUrl"], "http://dummy.com/md")
            self.assertEqual(
                resp["samlSettings"]["attributeMapping"],
                [{"name": "email", "type": "", "value": "attrVal1"}],
            )
            self.assertEqual(
                resp["samlSettings"]["groupsMapping"],
                [
                    {
                        "name": "grp1",
                        "type": "",
                        "filterType": "roles",
                        "value": "",
                        "roles": [{"id": "myRoleId", "name": "myRole"}],
                    }
                ],
            )
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_application_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "app1"},
                follow_redirects=None,
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
                await futu_await(client.mgmt.sso_application.load_all())

        # Test success flow
        with mock_http_call(self.async_test, "get") as mock_get:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = json.loads(
                """
                {
                    "apps": [
                        {"id":"app1","name":"App1","description":"","enabled":true,"logo":"","appType":"saml","samlSettings":{"loginPageUrl":"http://dummy.com/login","idpCert":"cert","useMetadataInfo":true,"metadataUrl":"http://dummy.com/md","entityId":"","acsUrl":"","certificate":"","attributeMapping":[{"name":"email","type":"","value":"attrVal1"}],"groupsMapping":[{"name":"grp1","type":"","filterType":"roles","value":"","roles":[{"id":"myRoleId","name":"myRole"}]}],"idpMetadataUrl":"","idpEntityId":"","idpSsoUrl":"","acsAllowedCallbacks":[],"subjectNameIdType":"","subjectNameIdFormat":""},"oidcSettings":{"loginPageUrl":"","issuer":"","discoveryUrl":""}},
                        {"id":"app2","name":"App2","description":"","enabled":true,"logo":"","appType":"oidc","samlSettings":{"loginPageUrl":"","idpCert":"","useMetadataInfo":false,"metadataUrl":"","entityId":"","acsUrl":"","certificate":"","attributeMapping":[],"groupsMapping":[],"idpMetadataUrl":"","idpEntityId":"","idpSsoUrl":"","acsAllowedCallbacks":[],"subjectNameIdType":"","subjectNameIdFormat":""},"oidcSettings":{"loginPageUrl":"http://dummy.com/login","issuer":"http://dummy.com/issuer","discoveryUrl":"http://dummy.com/wellknown"}}
                    ]
                }
                """
            )
            mock_get.return_value = network_resp
            resp = await futu_await(client.mgmt.sso_application.load_all())
            apps = resp["apps"]
            self.assertEqual(len(apps), 2)
            self.assertEqual(apps[0]["name"], "App1")
            self.assertEqual(apps[0]["appType"], "saml")
            self.assertEqual(
                apps[0]["samlSettings"]["loginPageUrl"], "http://dummy.com/login"
            )
            self.assertEqual(apps[0]["samlSettings"]["useMetadataInfo"], True)
            self.assertEqual(
                apps[0]["samlSettings"]["metadataUrl"], "http://dummy.com/md"
            )
            self.assertEqual(
                apps[0]["samlSettings"]["attributeMapping"],
                [{"name": "email", "type": "", "value": "attrVal1"}],
            )
            self.assertEqual(
                apps[0]["samlSettings"]["groupsMapping"],
                [
                    {
                        "name": "grp1",
                        "type": "",
                        "filterType": "roles",
                        "value": "",
                        "roles": [{"id": "myRoleId", "name": "myRole"}],
                    }
                ],
            )

            self.assertEqual(apps[1]["name"], "App2")
            self.assertEqual(apps[1]["appType"], "oidc")
            self.assertEqual(
                apps[1]["oidcSettings"]["loginPageUrl"], "http://dummy.com/login"
            )
            self.assertEqual(
                apps[1]["oidcSettings"]["issuer"], "http://dummy.com/issuer"
            )
            self.assertEqual(
                apps[1]["oidcSettings"]["discoveryUrl"], "http://dummy.com/wellknown"
            )
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_application_load_all_path}",
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
