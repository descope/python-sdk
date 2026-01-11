import logging

from descope import (
    AttributeMapping,
    AuthException,
    DescopeClient,
    OIDCAttributeMapping,
    RoleMapping,
    SSOOIDCSettings,
    SSOSAMLSettings,
    SSOSAMLSettingsByMetadata,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    management_key = ""
    tenant_id = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )

        try:
            logging.info("Configuring tenant with OIDC settings")
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
                groups_priority=["admin_group", "user_group"],
            )
            descope_client.mgmt.sso.configure_oidc_settings(tenant_id, settings)
        except AuthException as e:
            logging.info(f"Configure tenant OIDC settings failed {e}")

        try:
            logging.info("Load SSO settings for tenant - OIDC")
            settings_res = descope_client.mgmt.sso.load_settings(tenant_id)
            logging.info(f"SSO settings for tenant: {settings_res}")
        except AuthException as e:
            logging.info(f"Load SSO settings failed {e}")

        try:
            logging.info("Configuring tenant with SAML settings")
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
                role_mappings=[RoleMapping(groups=["grp1"], role_name="rl1")],
                groups_priority=["admin_group", "user_group"],
            )
            descope_client.mgmt.sso.configure_saml_settings(tenant_id, settings)
        except AuthException as e:
            logging.info(f"Configure tenant SAML settings failed {e}")

        try:
            logging.info("Load SSO settings for tenant - SAML")
            settings_res = descope_client.mgmt.sso.load_settings(tenant_id)
            logging.info(f"SSO settings for tenant: {settings_res}")
        except AuthException as e:
            logging.info(f"Load SSO settings failed {e}")

        try:
            logging.info("Configuring tenant with SAML settings by metadata")
            settings = SSOSAMLSettingsByMetadata(
                idp_metadata_url="https://dummy.com/metadata",
                attribute_mapping=AttributeMapping(
                    name="myName",
                    given_name="givenName",
                    middle_name="middleName",
                    family_name="familyName",
                    picture="picture",
                    email="email",
                    phone_number="phoneNumber",
                    group="groups",
                ),
                role_mappings=[RoleMapping(groups=["grp1"], role_name="rl1")],
                groups_priority=["admin_group", "user_group"],
            )
            descope_client.mgmt.sso.configure_saml_settings_by_metadata(
                tenant_id, settings, domains=["kuki.com"]
            )
        except AuthException as e:
            logging.info(f"Configure tenant SAML settings by metadata failed {e}")

        try:
            logging.info("Load SSO settings for tenant - SAML by metadata")
            settings_res = descope_client.mgmt.sso.load_settings(tenant_id)
            logging.info(f"SSO settings for tenant: {settings_res}")
        except AuthException as e:
            logging.info(f"Load SSO settings failed {e}")

        # All the following code is DEPRECATED (keeping just for backward compatibility)
        try:
            logging.info("Get SSO settings for tenant")
            settings_res = descope_client.mgmt.sso.get_settings(tenant_id)
            sso_tenant_domains = settings_res["domains"]
            logging.info(f"SSO domains for tenant: {sso_tenant_domains}")

        except AuthException as e:
            logging.info(f"Get SSO settings failed {e}")

        idp_url = ""
        entity_id = ""
        idp_cert = ""
        idp_metadata_url = ""
        redirect_url = ""
        domains = []
        role_mappings = [RoleMapping(["a"], "Tenant Admin")]
        attribute_mapping = AttributeMapping(name="MyName")

        try:
            logging.info("Configure SSO for tenant")
            descope_client.mgmt.sso.configure(
                tenant_id,
                idp_url=idp_url,
                entity_id=entity_id,
                idp_cert=idp_cert,
                redirect_url=redirect_url,
                domains=domains,
            )

        except AuthException as e:
            logging.info(f"SSO configuration failed {e}")

        try:
            logging.info("Configure SSO for tenant via metadata")
            descope_client.mgmt.sso.configure_via_metadata(
                tenant_id,
                idp_metadata_url=idp_metadata_url,
                redirect_url=redirect_url,
                domains=domains,
            )

        except AuthException as e:
            logging.info(f"SSO configuration failed via metadata {e}")

        try:
            logging.info("Update tenant role mappings")
            descope_client.mgmt.sso.mapping(
                tenant_id,
                role_mappings=role_mappings,
                attribute_mapping=attribute_mapping,
            )

        except AuthException as e:
            logging.info(f"SSO role mapping failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
