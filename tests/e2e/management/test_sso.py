"""E2E test: SSO settings (OIDC and SAML)."""

import os
import uuid

import pytest

from descope import (
    AttributeMapping,
    OIDCAttributeMapping,
    RoleMapping,
    SSOOIDCSettings,
    SSOSAMLSettings,
    SSOSAMLSettingsByMetadata,
)

pytestmark = pytest.mark.e2e


class TestE2E_ManagementSSO:
    async def test_management_sso_capabilities_oidc_settings(self, descope_client):
        tenant_name = f"sso-tenant-{uuid.uuid4().hex[:10]}"
        tid = (await descope_client.invoke(descope_client.mgmt.tenant.create(tenant_name)))["id"]

        try:
            settings = SSOOIDCSettings(
                name="myProvider",
                client_id="iddd",
                client_secret="secret",
                auth_url="https://dummy.com/auth",
                token_url="https://dummy.com/token",
                user_data_url="https://dummy.com/userInfo",
                scope=["openid", "profile", "email"],
                attribute_mapping=OIDCAttributeMapping(
                    login_id="subject",
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
            )
            await descope_client.invoke(descope_client.mgmt.sso.configure_oidc_settings(tid, settings))

            res = await descope_client.invoke(descope_client.mgmt.sso.load_settings(tid))
            oidc = res["oidc"]

            assert oidc["name"] == "myProvider"
            assert oidc["clientId"] == "iddd"
            assert oidc["clientSecret"] == ""  # redacted by backend
            assert oidc["authUrl"] == "https://dummy.com/auth"
            assert oidc["tokenUrl"] == "https://dummy.com/token"
            assert oidc["userDataUrl"] == "https://dummy.com/userInfo"
            assert oidc["scope"] == ["openid", "profile", "email"]

            mapping = oidc["userAttrMapping"]
            assert mapping["loginId"] == "subject"
            assert mapping["name"] == "name"
            assert mapping["givenName"] == "givenName"
            assert mapping["middleName"] == "middleName"
            assert mapping["familyName"] == "familyName"
            assert mapping["email"] == "email"
            assert mapping["verifiedEmail"] == "verifiedEmail"
            assert mapping["username"] == "username"
            assert mapping["phoneNumber"] == "phoneNumber"
            assert mapping["verifiedPhone"] == "verifiedPhone"
            assert mapping["picture"] == "picture"
        finally:
            await descope_client.invoke(descope_client.mgmt.tenant.delete(tid))

    async def test_management_sso_capabilities_saml_settings(self, descope_client):
        project_id = os.environ.get("DESCOPE_PROJECT_ID", "")
        role_name = f"sso-role-{uuid.uuid4().hex[:10]}"
        tenant_name = f"sso-tenant-{uuid.uuid4().hex[:10]}"

        await descope_client.invoke(descope_client.mgmt.role.create(role_name))
        tid = (await descope_client.invoke(descope_client.mgmt.tenant.create(tenant_name)))["id"]

        try:
            settings = SSOSAMLSettings(
                idp_url="https://dummy.com/saml",
                idp_entity_id="entity1234",
                idp_cert="my certificate",
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
                role_mappings=[RoleMapping(groups=["grp1"], role_name=role_name)],
            )
            await descope_client.invoke(descope_client.mgmt.sso.configure_saml_settings(tid, settings))

            res = await descope_client.invoke(descope_client.mgmt.sso.load_settings(tid))
            saml = res["saml"]

            assert saml["idpSSOUrl"] == "https://dummy.com/saml"
            assert saml["idpEntityId"] == "entity1234"
            assert saml["idpCertificate"] == "my certificate"
            assert saml["spEntityId"] == f"{project_id}-{tid}"
            assert f"projectId={project_id}" in saml["spACSUrl"]
            assert f"tenantId={tid}" in saml["spACSUrl"]

            attr_map = saml["attributeMapping"]
            assert attr_map["group"] == "groups"

            groups_mapping = saml["groupsMapping"]
            assert len(groups_mapping) == 1
            assert groups_mapping[0]["role"]["name"] == role_name
            assert groups_mapping[0]["groups"] == ["grp1"]
        finally:
            await descope_client.invoke(descope_client.mgmt.role.delete(role_name))
            await descope_client.invoke(descope_client.mgmt.tenant.delete(tid))

    async def test_management_sso_capabilities_saml_settings_by_metadata(self, descope_client):
        project_id = os.environ.get("DESCOPE_PROJECT_ID", "")
        role_name = f"sso-role-{uuid.uuid4().hex[:10]}"
        tenant_name = f"sso-tenant-{uuid.uuid4().hex[:10]}"

        await descope_client.invoke(descope_client.mgmt.role.create(role_name))
        tid = (await descope_client.invoke(descope_client.mgmt.tenant.create(tenant_name)))["id"]

        try:
            settings = SSOSAMLSettingsByMetadata(
                idp_metadata_url="https://dummy.com/saml",
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
                role_mappings=[RoleMapping(groups=["grp1"], role_name=role_name)],
            )
            await descope_client.invoke(descope_client.mgmt.sso.configure_saml_settings_by_metadata(tid, settings))

            res = await descope_client.invoke(descope_client.mgmt.sso.load_settings(tid))
            saml = res["saml"]

            assert saml["idpMetadataUrl"] == "https://dummy.com/saml"
            assert saml["spEntityId"] == f"{project_id}-{tid}"
            assert f"projectId={project_id}" in saml["spACSUrl"]
            assert f"tenantId={tid}" in saml["spACSUrl"]

            attr_map = saml["attributeMapping"]
            assert attr_map["group"] == "groups"

            groups_mapping = saml["groupsMapping"]
            assert len(groups_mapping) == 1
            assert groups_mapping[0]["role"]["name"] == role_name
            assert groups_mapping[0]["groups"] == ["grp1"]
        finally:
            await descope_client.invoke(descope_client.mgmt.role.delete(role_name))
            await descope_client.invoke(descope_client.mgmt.tenant.delete(tid))

    async def test_management_sso_capabilities(self, descope_client):
        # NOTE: These APIs are deprecated; retained for backwards-compatibility parity.
        project_id = os.environ.get("DESCOPE_PROJECT_ID", "")
        tenant_name = f"sso-tenant-{uuid.uuid4().hex[:10]}"
        tid = (await descope_client.invoke(descope_client.mgmt.tenant.create(tenant_name)))["id"]

        try:
            loaded = await descope_client.invoke(descope_client.mgmt.tenant.load(tid))
            assert loaded["id"] == tid
            assert loaded["name"] == tenant_name

            # --- Initial empty state ---
            settings = await descope_client.invoke(descope_client.mgmt.sso.get_settings(tid))
            assert settings["tenantId"]
            assert settings["idpEntityId"] == ""
            assert settings["idpSSOUrl"] == ""
            assert settings["idpCertificate"] == ""
            assert settings.get("idpMetadataUrl", "") == ""
            assert settings["spEntityId"] == f"{project_id}-{tid}"
            assert f"projectId={project_id}" in settings["spACSUrl"]
            assert f"tenantId={tid}" in settings["spACSUrl"]
            assert settings.get("groupsMapping", []) == []
            assert settings.get("redirectUrl", "") == ""
            assert settings.get("domain", "") == ""
            assert settings.get("domains", []) == []
            assert settings.get("userMapping", {}) == {
                "name": "name",
                "email": "email",
                "username": "",
                "phoneNumber": "phone",
                "group": "",
                "givenName": "",
                "middleName": "",
                "familyName": "",
                "picture": "",
                "verifiedEmail": "",
                "verifiedPhone": "",
                "customAttributes": {},
            }

            await descope_client.invoke(
                descope_client.mgmt.sso.configure(
                    tid,
                    "http://idpURL",
                    "entity",
                    "mycert",
                    "https://redirect",
                    ["domain.com", "app.domain.com"],
                )
            )

            settings = await descope_client.invoke(descope_client.mgmt.sso.get_settings(tid))
            assert settings["idpEntityId"] == "entity"
            assert settings["idpSSOUrl"] == "http://idpURL"
            assert settings["idpCertificate"] == "mycert"
            assert settings["spEntityId"] == f"{project_id}-{tid}"
            assert f"projectId={project_id}" in settings["spACSUrl"]
            assert f"tenantId={tid}" in settings["spACSUrl"]
            assert settings["redirectUrl"] == "https://redirect"
            assert settings.get("domain", "") == "domain.com"
            assert "domain.com" in settings["domains"]
            assert "app.domain.com" in settings["domains"]

            await descope_client.invoke(
                descope_client.mgmt.sso.configure_via_metadata(
                    tid,
                    "http://idpMetadataURL",
                    domains=["domain2.com", "app.domain2.com"],
                )
            )

            await descope_client.invoke(
                descope_client.mgmt.sso.mapping(
                    tid,
                    role_mappings=[RoleMapping(["a"], "Tenant Admin")],
                    attribute_mapping=AttributeMapping(name="MyName"),
                )
            )

            settings = await descope_client.invoke(descope_client.mgmt.sso.get_settings(tid))
            assert settings.get("idpMetadataUrl") == "http://idpMetadataURL"
            assert settings["spEntityId"] == f"{project_id}-{tid}"
            assert f"projectId={project_id}" in settings["spACSUrl"]
            assert f"tenantId={tid}" in settings["spACSUrl"]
            assert settings.get("redirectUrl", "") == "https://redirect"
            assert settings.get("domain", "") == "domain2.com"
            assert "domain2.com" in settings["domains"]
            user_mapping = settings.get("userMapping", {})
            assert user_mapping == {
                "name": "MyName",
                "email": "",
                "username": "",
                "phoneNumber": "",
                "group": "",
                "givenName": "",
                "middleName": "",
                "familyName": "",
                "picture": "",
                "verifiedEmail": "",
                "verifiedPhone": "",
                "customAttributes": {},
            }
            groups_mapping = settings.get("groupsMapping", [])
            assert len(groups_mapping) == 1
            assert groups_mapping[0]["role"]["name"] == "Tenant Admin"
            assert groups_mapping[0]["groups"] == ["a"]

            await descope_client.invoke(descope_client.mgmt.sso.delete_settings(tid))

            settings = await descope_client.invoke(descope_client.mgmt.sso.get_settings(tid))
            assert settings["idpEntityId"] == ""
            assert settings["idpSSOUrl"] == ""
            assert settings["idpCertificate"] == ""
        finally:
            await descope_client.invoke(descope_client.mgmt.tenant.delete(tid))
