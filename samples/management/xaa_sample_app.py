import logging

from descope import (
    AttributeMapping,
    AuthException,
    DescopeClient,
    RoleMapping,
    XAAIssuerSettings,
    XAAJWTBearerSettings,
    XAASettings,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    management_key = ""

    try:
        descope_client = DescopeClient(project_id=project_id, management_key=management_key)
        tenant_id = ""
        # sso_id addresses a single SSO configuration of the tenant. Leave it empty ("") to target
        # the tenant's default SSO configuration.
        sso_id = ""

        # Cross-App Access (XAA / ID-JAG) trust is configured per SSO configuration of a tenant, through
        # the SSO management API. The trusted issuers are set together with the config-level shared
        # group/role mapping (shared across SAML / OIDC / SCIM / XAA for the sso_id).
        try:
            logging.info("Configuring XAA (ID-JAG) trusted issuers + shared mapping")
            descope_client.mgmt.sso.configure_xaa_settings(
                tenant_id,
                XAASettings(
                    enabled=True,
                    settings=XAAJWTBearerSettings(
                        issuers={
                            # Key is the trusted issuer URL.
                            "https://issuer.example.com": XAAIssuerSettings(
                                jwks_uri="https://issuer.example.com/.well-known/jwks.json",
                                sign_algorithm="RS256",
                                user_info_uri="https://issuer.example.com/userinfo",
                                # assertion claim used as the login id
                                external_id_field_name="sub",
                                # JIT provisioning on: create/update the user from the assertion
                                jit_disabled=False,
                                attribute_mapping=AttributeMapping(
                                    email="email",
                                    name="name",
                                    # assertion claim that carries the user's groups.
                                    # NOTE: how those group names resolve to roles is defined once,
                                    # per SSO configuration, via the shared mapping below.
                                    group="groups",
                                ),
                            ),
                        },
                    ),
                    # Config-level shared group/role mapping (shared across SAML / OIDC / SCIM / XAA).
                    role_mappings=[RoleMapping(groups=["admins"], role_name="Tenant Admin")],
                    default_sso_roles=["Member"],
                ),
                sso_id=sso_id,
            )
            logging.info("XAA settings configured")

        except AuthException as e:
            logging.info(f"XAA configure failed {e}")

        try:
            logging.info("Loading the XAA settings for a single SSO configuration")
            xaa = descope_client.mgmt.sso.load_xaa_settings(tenant_id, sso_id)
            logging.info(f"Loaded XAA settings: {xaa}")

        except AuthException as e:
            logging.info(f"XAA load failed {e}")

        try:
            logging.info("Loading the XAA settings for every SSO configuration of the tenant")
            all_xaa = descope_client.mgmt.sso.load_all_xaa_settings(tenant_id)
            logging.info(f"Loaded all XAA settings: {all_xaa}")

        except AuthException as e:
            logging.info(f"XAA load-all failed {e}")

        try:
            logging.info("Deleting the XAA settings of a single SSO configuration")
            # Removes the configuration's trusted issuers from the tenant's ID-JAG runtime index.
            descope_client.mgmt.sso.delete_xaa_settings(tenant_id, sso_id)

        except AuthException as e:
            logging.info(f"XAA delete failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
