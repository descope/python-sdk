import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import (
    AuthException,
    DescopeClient,
    RoleMapping,
    AttributeMapping,
)  # noqa: E402

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    management_key = ""
    tenant_id = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )
        idp_url = ""
        entity_id = ""
        idp_cert = ""
        idp_metadata_url = ""
        role_mappings = [RoleMapping(["a"], "Tenant Admin")]
        attribute_mapping = AttributeMapping(name="MyName")

        try:
            logging.info("Configure SSO for tenant")
            descope_client.mgmt.sso.configure(
                tenant_id,
                idp_url=idp_url,
                entity_id=entity_id,
                idp_cert=idp_cert,
            )

        except AuthException as e:
            logging.info(f"SSO configuration failed {e}")

        try:
            logging.info("Configure SSO for tenant via metadata")
            descope_client.mgmt.sso.configure_via_metadata(
                tenant_id,
                idp_metadata_url=idp_metadata_url,
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
