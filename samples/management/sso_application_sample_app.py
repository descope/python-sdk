import logging

from descope import (
    AuthException,
    DescopeClient,
    SAMLIDPAttributeMappingInfo,
    SAMLIDPGroupsMappingInfo,
    SAMLIDPRoleGroupMappingInfo,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    management_key = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )
        sso_app_id = ""

        # OIDC APP

        try:
            logging.info("Going to create a new OIDC sso application")
            resp = descope_client.mgmt.sso_application.create_oidc_application(
                "My first OIDC sso application", "http://dummy.com"
            )
            sso_app_id = resp["id"]
            logging.info(f"SSO application creation response: {resp}")

        except AuthException as e:
            logging.info(f"SSO application creation failed {e}")

        try:
            logging.info("Loading SSO application by id")
            sso_app_resp = descope_client.mgmt.sso_application.load(sso_app_id)
            logging.info(f"Found sso application {sso_app_resp}")

        except AuthException as e:
            logging.info(f"Permission load failed {e}")

        try:
            logging.info("Loading all sso applications")
            sso_app_resp = descope_client.mgmt.sso_application.load_all()
            apps = sso_app_resp["apps"]
            for app in apps:
                logging.info(f"LoadAll Found sso application: {app}")

        except AuthException as e:
            logging.info(f"Permission load failed {e}")

        try:
            logging.info("Updating newly created OIDC sso application")
            # update overrides all fields, must provide the entire entity
            # we mean to update.
            descope_client.mgmt.sso_application.update_oidc_application(
                id=sso_app_id,
                name="My First OIDC sso application",
                login_page_url="http://newdummy.com",
                enabled=False,
            )

        except AuthException as e:
            logging.info(f"sso application update failed {e}")

        try:
            logging.info("Deleting newly created OIDC sso application")
            descope_client.mgmt.sso_application.delete(sso_app_id)

        except AuthException as e:
            logging.info(f"sso application deletion failed {e}")

        # SAML APP

        try:
            logging.info("Going to create a new SAML sso application")
            resp = descope_client.mgmt.sso_application.create_saml_application(
                name="My first SAML sso application",
                login_page_url="http://dummy.com",
                use_metadata_info=True,
                metadata_url="http://dummy.com/metadata",
                attribute_mapping=[
                    SAMLIDPAttributeMappingInfo("email", "", "attrVal1")
                ],
                groups_mapping=[
                    SAMLIDPGroupsMappingInfo(
                        "grp1",
                        "",
                        "roles",
                        "",
                        [SAMLIDPRoleGroupMappingInfo("myRoleId", "myRole")],
                    )
                ],
                subject_name_id_type="email",
            )
            sso_app_id = resp["id"]
            logging.info(f"SSO application creation response: {resp}")

        except AuthException as e:
            logging.info(f"SSO application creation failed {e}")

        try:
            logging.info("Loading SSO application by id")
            sso_app_resp = descope_client.mgmt.sso_application.load(sso_app_id)
            logging.info(f"Found sso application {sso_app_resp}")

        except AuthException as e:
            logging.info(f"Permission load failed {e}")

        try:
            logging.info("Loading all sso applications")
            sso_app_resp = descope_client.mgmt.sso_application.load_all()
            apps = sso_app_resp["apps"]
            for app in apps:
                logging.info(f"LoadAll Found sso application: {app}")

        except AuthException as e:
            logging.info(f"Permission load failed {e}")

        try:
            logging.info("Updating newly created SAML sso application")
            # update overrides all fields, must provide the entire entity
            # we mean to update.
            descope_client.mgmt.sso_application.update_saml_application(
                id=sso_app_id,
                name="My First SAML sso application",
                login_page_url="http://newdummy.com",
                enabled=False,
                use_metadata_info=False,
                entity_id="entity1234",
                acs_url="http://dummy.com/acs",
                certificate="my cert",
                subject_name_id_type="",
            )

        except AuthException as e:
            logging.info(f"sso application update failed {e}")

        try:
            logging.info("Deleting newly created SAML sso application")
            descope_client.mgmt.sso_application.delete(sso_app_id)

        except AuthException as e:
            logging.info(f"sso application deletion failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
