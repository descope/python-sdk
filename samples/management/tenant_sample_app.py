import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import AuthException, DescopeClient  # noqa: E402

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    management_key = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )
        tenant_id = ""

        try:
            logging.info("Going to create a new tenant")
            resp = descope_client.mgmt.tenant.create("My First Tenant")
            tenant_id = resp["id"]
            logging.info(f"Tenant creation response: {resp}")

        except AuthException as e:
            logging.info(f"Tenant creation failed {e}")

        try:
            logging.info("Loading tenant by id")
            tenant_resp = descope_client.mgmt.tenant.load(tenant_id)
            logging.info(f"Found tenant {tenant_resp}")

        except AuthException as e:
            logging.info(f"Permission load failed {e}")

        try:
            logging.info("Loading all tenants")
            tenants_resp = descope_client.mgmt.tenant.load_all()
            tenants = tenants_resp["tenants"]
            for tenant in tenants:
                logging.info(f"Search Found tenant {tenant}")

        except AuthException as e:
            logging.info(f"Permission load failed {e}")

        try:
            logging.info("Updating newly created tenant")
            # update overrides all fields, must provide the entire entity
            # we mean to update.
            descope_client.mgmt.tenant.update(
                tenant_id, "My First Tenant", ["mydomain.com"]
            )

        except AuthException as e:
            logging.info(f"Tenant update failed {e}")

        try:
            logging.info("Deleting newly created tenant")
            descope_client.mgmt.tenant.delete(tenant_id)

        except AuthException as e:
            logging.info(f"Tenant deletion failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
