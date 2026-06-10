import pytest

from descope import (
    AuthException,
    SAMLIDPAttributeMappingInfo,
    SAMLIDPGroupsMappingInfo,
    SAMLIDPRoleGroupMappingInfo,
)
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestSSOApplication:
    async def test_create_oidc_application(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=400)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso_application.create_oidc_application(
                        "valid-name",
                        "http://dummy.com",
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"id": "app1"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.sso_application.create_oidc_application(
                    name="name",
                    login_page_url="http://dummy.com",
                    force_authentication=True,
                )
            )
            assert resp["id"] == "app1"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_application_oidc_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_create_saml_application(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows — validation errors (no HTTP call needed)
        with pytest.raises(Exception):
            await client.invoke(
                client.mgmt.sso_application.create_saml_application(
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=True,
                    metadata_url="",
                )
            )

        with pytest.raises(Exception):
            await client.invoke(
                client.mgmt.sso_application.create_saml_application(
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=False,
                    entity_id="",
                )
            )

        with client.mock_mgmt_post(make_response(status=400)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso_application.create_saml_application(
                        name="valid-name",
                        login_page_url="http://dummy.com",
                        use_metadata_info=True,
                        metadata_url="http://dummy.com/md",
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"id": "app1"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.sso_application.create_saml_application(
                    name="name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=True,
                    metadata_url="http://dummy.com/md",
                    attribute_mapping=[SAMLIDPAttributeMappingInfo("name1", "type1", "val1")],
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
                    default_signature_algorithm="sha256",
                )
            )
            assert resp["id"] == "app1"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_application_saml_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                    "attributeMapping": [{"name": "name1", "type": "type1", "value": "val1"}],
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
                    "defaultSignatureAlgorithm": "sha256",
                },
                follow_redirects=False,
            )

    async def test_update_oidc_application(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=400)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso_application.update_oidc_application(
                        "id1",
                        "valid-name",
                        "http://dummy.com",
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso_application.update_oidc_application(
                    "app1",
                    "name",
                    "http://dummy.com",
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_application_oidc_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_update_saml_application(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows — validation errors (no HTTP call needed)
        with pytest.raises(Exception):
            await client.invoke(
                client.mgmt.sso_application.update_saml_application(
                    id="id1",
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=True,
                    metadata_url="",
                )
            )

        with pytest.raises(Exception):
            await client.invoke(
                client.mgmt.sso_application.update_saml_application(
                    id="id1",
                    name="valid-name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=False,
                    entity_id="",
                )
            )

        with client.mock_mgmt_post(make_response(status=400)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso_application.update_saml_application(
                        id="id1",
                        name="valid-name",
                        login_page_url="http://dummy.com",
                        use_metadata_info=True,
                        metadata_url="http://dummy.com/md",
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso_application.update_saml_application(
                    id="id1",
                    name="name",
                    login_page_url="http://dummy.com",
                    use_metadata_info=False,
                    metadata_url="",
                    entity_id="ent1234",
                    acs_url="http://dummy.com/acs",
                    certificate="cert",
                    attribute_mapping=[SAMLIDPAttributeMappingInfo("name1", "type1", "val1")],
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
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_application_saml_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                    "attributeMapping": [{"name": "name1", "type": "type1", "value": "val1"}],
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
                    "defaultSignatureAlgorithm": None,
                },
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=400)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso_application.delete("valid-id")
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.sso_application.delete("app1"))
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_application_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "app1",
                },
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=400)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.sso_application.load("valid-id"))

        # Test success flow
        load_resp = {
            "id": "app1",
            "name": "App1",
            "description": "",
            "enabled": True,
            "logo": "",
            "appType": "saml",
            "samlSettings": {
                "loginPageUrl": "http://dummy.com/login",
                "idpCert": "cert",
                "useMetadataInfo": True,
                "metadataUrl": "http://dummy.com/md",
                "entityId": "",
                "acsUrl": "",
                "certificate": "",
                "attributeMapping": [{"name": "email", "type": "", "value": "attrVal1"}],
                "groupsMapping": [
                    {
                        "name": "grp1",
                        "type": "",
                        "filterType": "roles",
                        "value": "",
                        "roles": [{"id": "myRoleId", "name": "myRole"}],
                    }
                ],
                "idpMetadataUrl": "",
                "idpEntityId": "",
                "idpSsoUrl": "",
                "acsAllowedCallbacks": [],
                "subjectNameIdType": "",
                "subjectNameIdFormat": "",
            },
            "oidcSettings": {"loginPageUrl": "", "issuer": "", "discoveryUrl": ""},
        }
        with client.mock_mgmt_get(make_response(load_resp)) as mock_get:
            resp = await client.invoke(client.mgmt.sso_application.load("app1"))
            assert resp["name"] == "App1"
            assert resp["appType"] == "saml"
            assert resp["samlSettings"]["loginPageUrl"] == "http://dummy.com/login"
            assert resp["samlSettings"]["useMetadataInfo"] is True
            assert resp["samlSettings"]["metadataUrl"] == "http://dummy.com/md"
            assert resp["samlSettings"]["attributeMapping"] == [
                {"name": "email", "type": "", "value": "attrVal1"}
            ]
            assert resp["samlSettings"]["groupsMapping"] == [
                {
                    "name": "grp1",
                    "type": "",
                    "filterType": "roles",
                    "value": "",
                    "roles": [{"id": "myRoleId", "name": "myRole"}],
                }
            ]
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_application_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"id": "app1"},
                follow_redirects=True,
            )

    async def test_load_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=400)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.sso_application.load_all())

        # Test success flow
        load_all_resp = {
            "apps": [
                {
                    "id": "app1",
                    "name": "App1",
                    "description": "",
                    "enabled": True,
                    "logo": "",
                    "appType": "saml",
                    "samlSettings": {
                        "loginPageUrl": "http://dummy.com/login",
                        "idpCert": "cert",
                        "useMetadataInfo": True,
                        "metadataUrl": "http://dummy.com/md",
                        "entityId": "",
                        "acsUrl": "",
                        "certificate": "",
                        "attributeMapping": [{"name": "email", "type": "", "value": "attrVal1"}],
                        "groupsMapping": [
                            {
                                "name": "grp1",
                                "type": "",
                                "filterType": "roles",
                                "value": "",
                                "roles": [{"id": "myRoleId", "name": "myRole"}],
                            }
                        ],
                        "idpMetadataUrl": "",
                        "idpEntityId": "",
                        "idpSsoUrl": "",
                        "acsAllowedCallbacks": [],
                        "subjectNameIdType": "",
                        "subjectNameIdFormat": "",
                    },
                    "oidcSettings": {"loginPageUrl": "", "issuer": "", "discoveryUrl": ""},
                },
                {
                    "id": "app2",
                    "name": "App2",
                    "description": "",
                    "enabled": True,
                    "logo": "",
                    "appType": "oidc",
                    "samlSettings": {
                        "loginPageUrl": "",
                        "idpCert": "",
                        "useMetadataInfo": False,
                        "metadataUrl": "",
                        "entityId": "",
                        "acsUrl": "",
                        "certificate": "",
                        "attributeMapping": [],
                        "groupsMapping": [],
                        "idpMetadataUrl": "",
                        "idpEntityId": "",
                        "idpSsoUrl": "",
                        "acsAllowedCallbacks": [],
                        "subjectNameIdType": "",
                        "subjectNameIdFormat": "",
                    },
                    "oidcSettings": {
                        "loginPageUrl": "http://dummy.com/login",
                        "issuer": "http://dummy.com/issuer",
                        "discoveryUrl": "http://dummy.com/wellknown",
                    },
                },
            ]
        }
        with client.mock_mgmt_get(make_response(load_all_resp)) as mock_get:
            resp = await client.invoke(client.mgmt.sso_application.load_all())
            apps = resp["apps"]
            assert len(apps) == 2
            assert apps[0]["name"] == "App1"
            assert apps[0]["appType"] == "saml"
            assert apps[0]["samlSettings"]["loginPageUrl"] == "http://dummy.com/login"
            assert apps[0]["samlSettings"]["useMetadataInfo"] is True
            assert apps[0]["samlSettings"]["metadataUrl"] == "http://dummy.com/md"
            assert apps[0]["samlSettings"]["attributeMapping"] == [
                {"name": "email", "type": "", "value": "attrVal1"}
            ]
            assert apps[0]["samlSettings"]["groupsMapping"] == [
                {
                    "name": "grp1",
                    "type": "",
                    "filterType": "roles",
                    "value": "",
                    "roles": [{"id": "myRoleId", "name": "myRole"}],
                }
            ]
            assert apps[1]["name"] == "App2"
            assert apps[1]["appType"] == "oidc"
            assert apps[1]["oidcSettings"]["loginPageUrl"] == "http://dummy.com/login"
            assert apps[1]["oidcSettings"]["issuer"] == "http://dummy.com/issuer"
            assert apps[1]["oidcSettings"]["discoveryUrl"] == "http://dummy.com/wellknown"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_application_load_all_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                follow_redirects=True,
            )
