import json

import pytest

from descope import AttributeMapping, AuthException, RoleMapping
from descope.management.common import MgmtV1
from descope.management.sso_settings import (
    FGAGroupMapping,
    FGAGroupMappingRelation,
    OIDCAttributeMapping,
    SSOOIDCSettings,
    SSOSAMLSettings,
    SSOSAMLSettingsByMetadata,
    SSOSettings,
)

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT


class TestSSOSettings:
    async def test_delete_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_delete(make_response(status=500)) as mock_delete:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.sso.delete_settings("tenant-id"))

        # Test success flow
        with client.mock_mgmt_delete(make_response()) as mock_delete:
            await client.invoke(client.mgmt.sso.delete_settings("tenant-id"))

            assert_http_called(
                mock_delete,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                params={"tenantId": "tenant-id"},
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                follow_redirects=False,
            )

    async def test_load_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.sso.load_settings("tenant-id"))

        # Test success flow
        resp_data = json.loads(
            """{"tenant": {"id": "T2AAAA", "name": "myTenantName", "selfProvisioningDomains": [], "customAttributes": {}, "authType": "saml", "domains": ["lulu", "kuku"]}, "saml": {"idpEntityId": "", "idpSSOUrl": "", "idpCertificate": "", "idpAdditionalCertificates": ["cert1", "cert2"], "defaultSSORoles": ["aa", "bb"], "idpMetadataUrl": "https://dummy.com/metadata", "spEntityId": "", "spACSUrl": "", "spCertificate": "", "attributeMapping": {"name": "name", "email": "email", "username": "", "phoneNumber": "phone", "group": "", "givenName": "", "middleName": "", "familyName": "", "picture": "", "customAttributes": {}}, "groupsMapping": [], "redirectUrl": ""}, "oidc": {"name": "", "clientId": "", "clientSecret": "", "redirectUrl": "", "authUrl": "", "tokenUrl": "", "userDataUrl": "", "scope": [], "JWKsUrl": "", "userAttrMapping": {"loginId": "sub", "username": "", "name": "name", "email": "email", "phoneNumber": "phone_number", "verifiedEmail": "email_verified", "verifiedPhone": "phone_number_verified", "picture": "picture", "givenName": "given_name", "middleName": "middle_name", "familyName": "family_name"}, "manageProviderTokens": false, "callbackDomain": "", "prompt": [], "grantType": "authorization_code", "issuer": ""}}"""
        )
        with client.mock_mgmt_get(make_response(resp_data)) as mock_get:
            resp = await client.invoke(client.mgmt.sso.load_settings("T2AAAA"))
            tenant = resp.get("tenant", {})
            assert tenant.get("id", "") == "T2AAAA"
            assert tenant.get("domains", []) == ["lulu", "kuku"]
            saml_settings = resp.get("saml", {})
            assert saml_settings.get("idpMetadataUrl", "") == "https://dummy.com/metadata"
            assert saml_settings.get("defaultSSORoles", "") == ["aa", "bb"]
            assert saml_settings.get("idpAdditionalCertificates", []) == ["cert1", "cert2"]
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_load_settings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"tenantId": "T2AAAA"},
                follow_redirects=True,
            )

    async def test_configure_oidc_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso.configure_oidc_settings(
                        "tenant-id",
                        SSOOIDCSettings(
                            name="myName",
                            client_id="cid",
                        ),
                        ["domain.com"],
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
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
                        groups_priority=["group1"],
                    ),
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_configure_oidc_settings}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                        "groupsPriority": ["group1"],
                        "fgaMappings": None,
                    },
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
            )

    async def test_configure_saml_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso.configure_saml_settings(
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
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
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
                        groups_priority=["group1"],
                    ),
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_configure_saml_settings}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                        "groupsPriority": ["group1"],
                        "fgaMappings": None,
                        "configFGATenantIDResourcePrefix": None,
                        "configFGATenantIDResourceSuffix": None,
                    },
                    "redirectUrl": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
            )

    async def test_configure_saml_settings_by_metadata(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso.configure_saml_settings_by_metadata(
                        "tenant-id",
                        SSOSAMLSettingsByMetadata(idp_metadata_url="http://dummy.com/metadata"),
                        "https://redirect.com",
                        ["domain.com"],
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
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
                        groups_priority=["group1"],
                    ),
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_configure_saml_by_metadata_settings}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                        "groupsPriority": ["group1"],
                        "fgaMappings": None,
                        "configFGATenantIDResourcePrefix": None,
                        "configFGATenantIDResourceSuffix": None,
                    },
                    "redirectUrl": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
            )

    async def test_configure_saml_settings_with_additional_certs(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow with additional certs
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
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
                        groups_priority=["group1"],
                    ),
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_configure_saml_settings}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                        "groupsPriority": ["group1"],
                        "fgaMappings": None,
                        "configFGATenantIDResourcePrefix": None,
                        "configFGATenantIDResourceSuffix": None,
                    },
                    "redirectUrl": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
            )

    def test_attribute_mapping_to_dict(self):
        with pytest.raises(ValueError):
            SSOSettings._attribute_mapping_to_dict(None)

    def test_fga_mappings_to_dict(self):
        # None input returns None
        assert SSOSettings._fga_mappings_to_dict(None) is None

        # Empty dict returns empty dict
        assert SSOSettings._fga_mappings_to_dict({}) == {}

        # Group with relations is serialized into camelCase keys
        mappings = {
            "admins": FGAGroupMapping(
                relations=[
                    FGAGroupMappingRelation(
                        resource="tenant:t1",
                        relation_definition="member",
                        namespace="tenant",
                    ),
                    FGAGroupMappingRelation(
                        resource="tenant:t1",
                        relation_definition="owner",
                        namespace="tenant",
                    ),
                ],
            ),
            "viewers": FGAGroupMapping(),
        }
        assert SSOSettings._fga_mappings_to_dict(mappings) == {
            "admins": {
                "relations": [
                    {
                        "resource": "tenant:t1",
                        "relationDefinition": "member",
                        "namespace": "tenant",
                    },
                    {
                        "resource": "tenant:t1",
                        "relationDefinition": "owner",
                        "namespace": "tenant",
                    },
                ],
            },
            "viewers": {"relations": []},
        }

    async def test_configure_saml_settings_with_fga_mappings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure_saml_settings(
                    "tenant-id",
                    SSOSAMLSettings(
                        idp_url="http://dummy.com",
                        idp_entity_id="ent1234",
                        idp_cert="cert",
                        fga_mappings={
                            "admins": FGAGroupMapping(
                                relations=[
                                    FGAGroupMappingRelation(
                                        resource="tenant:t1",
                                        relation_definition="member",
                                        namespace="tenant",
                                    ),
                                ],
                            ),
                        },
                        config_fga_tenant_id_resource_prefix="tenant:",
                        config_fga_tenant_id_resource_suffix="",
                    ),
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_configure_saml_settings}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "settings": {
                        "idpUrl": "http://dummy.com",
                        "entityId": "ent1234",
                        "idpCert": "cert",
                        "idpAdditionalCerts": None,
                        "attributeMapping": None,
                        "roleMappings": [],
                        "spACSUrl": None,
                        "spEntityId": None,
                        "defaultSSORoles": None,
                        "groupsPriority": None,
                        "fgaMappings": {
                            "admins": {
                                "relations": [
                                    {
                                        "resource": "tenant:t1",
                                        "relationDefinition": "member",
                                        "namespace": "tenant",
                                    },
                                ],
                            },
                        },
                        "configFGATenantIDResourcePrefix": "tenant:",
                        "configFGATenantIDResourceSuffix": "",
                    },
                    "redirectUrl": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
            )

    async def test_configure_saml_settings_by_metadata_with_fga_mappings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure_saml_settings_by_metadata(
                    "tenant-id",
                    SSOSAMLSettingsByMetadata(
                        idp_metadata_url="http://dummy.com/metadata",
                        fga_mappings={
                            "admins": FGAGroupMapping(
                                relations=[
                                    FGAGroupMappingRelation(
                                        resource="tenant:t1",
                                        relation_definition="member",
                                        namespace="tenant",
                                    ),
                                ],
                            ),
                        },
                        config_fga_tenant_id_resource_prefix="tenant:",
                        config_fga_tenant_id_resource_suffix="-suffix",
                    ),
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_configure_saml_by_metadata_settings}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "settings": {
                        "idpMetadataUrl": "http://dummy.com/metadata",
                        "attributeMapping": None,
                        "roleMappings": [],
                        "spACSUrl": None,
                        "spEntityId": None,
                        "defaultSSORoles": None,
                        "groupsPriority": None,
                        "fgaMappings": {
                            "admins": {
                                "relations": [
                                    {
                                        "resource": "tenant:t1",
                                        "relationDefinition": "member",
                                        "namespace": "tenant",
                                    },
                                ],
                            },
                        },
                        "configFGATenantIDResourcePrefix": "tenant:",
                        "configFGATenantIDResourceSuffix": "-suffix",
                    },
                    "redirectUrl": None,
                    "domains": None,
                },
                follow_redirects=False,
            )

    async def test_configure_oidc_settings_with_fga_mappings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure_oidc_settings(
                    "tenant-id",
                    SSOOIDCSettings(
                        name="myName",
                        client_id="cid",
                        fga_mappings={
                            "admins": FGAGroupMapping(
                                relations=[
                                    FGAGroupMappingRelation(
                                        resource="tenant:t1",
                                        relation_definition="member",
                                        namespace="tenant",
                                    ),
                                ],
                            ),
                        },
                    ),
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_configure_oidc_settings}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "settings": {
                        "name": "myName",
                        "clientId": "cid",
                        "clientSecret": None,
                        "redirectUrl": None,
                        "authUrl": None,
                        "tokenUrl": None,
                        "userDataUrl": None,
                        "scope": None,
                        "JWKsUrl": None,
                        "userAttrMapping": None,
                        "manageProviderTokens": False,
                        "callbackDomain": None,
                        "prompt": None,
                        "grantType": None,
                        "issuer": None,
                        "groupsPriority": None,
                        "fgaMappings": {
                            "admins": {
                                "relations": [
                                    {
                                        "resource": "tenant:t1",
                                        "relationDefinition": "member",
                                        "namespace": "tenant",
                                    },
                                ],
                            },
                        },
                    },
                    "domains": None,
                },
                follow_redirects=False,
            )

    # Testing DEPRECATED functions
    async def test_get_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.sso.get_settings("tenant-id"))

        # Test success flow
        with client.mock_mgmt_get(make_response({"domains": ["lulu", "kuku"], "tenantId": "tenant-id"})) as mock_get:
            resp = await client.invoke(client.mgmt.sso.get_settings("tenant-id"))
            assert resp["tenantId"] == "tenant-id"
            assert resp["domains"] == ["lulu", "kuku"]
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"tenantId": "tenant-id"},
                follow_redirects=True,
            )

    async def test_configure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso.configure(
                        "tenant-id",
                        "https://idp.com",
                        "entity-id",
                        "cert",
                        "https://redirect.com",
                        ["domain.com"],
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Domain is optional
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "https://redirect.com",
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Redirect is optional
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "",
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_configure_via_metadata(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso.configure_via_metadata(
                        "tenant-id",
                        "https://idp-meta.com",
                        "https://redirect.com",
                        ["domain.com"],
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure_via_metadata(
                    "tenant-id",
                    "https://idp-meta.com",
                    "https://redirect.com",
                    ["domain.com"],
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_metadata_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpMetadataURL": "https://idp-meta.com",
                    "redirectURL": "https://redirect.com",
                    "domains": ["domain.com"],
                },
                follow_redirects=False,
            )

        # Test partial arguments
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.configure_via_metadata(
                    "tenant-id",
                    "https://idp-meta.com",
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_metadata_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpMetadataURL": "https://idp-meta.com",
                    "redirectURL": None,
                    "domains": None,
                },
                follow_redirects=False,
            )

    async def test_mapping(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.sso.mapping(
                        "tenant-id",
                        [RoleMapping(["a", "b"], "role")],
                        AttributeMapping(name="UName"),
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.sso.mapping(
                    "tenant-id",
                    [RoleMapping(["a", "b"], "role")],
                    AttributeMapping(name="UName"),
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_mapping_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_recalculate_sso_mappings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.sso.recalculate_sso_mappings("tenant-id"))

        # Test success flow with sso_id
        with client.mock_mgmt_post(make_response({"affectedUserIds": ["user1", "user2", "user3"]})) as mock_post:
            await client.invoke(client.mgmt.sso.recalculate_sso_mappings("tenant-id", "sso-456"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_recalculate_mappings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "ssoId": "sso-456",
                },
                follow_redirects=False,
            )

        # Test success flow without sso_id
        with client.mock_mgmt_post(make_response({"affectedUserIds": ["user1"]})) as mock_post:
            await client.invoke(client.mgmt.sso.recalculate_sso_mappings("tenant-id"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.sso_recalculate_mappings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                },
                follow_redirects=False,
            )
