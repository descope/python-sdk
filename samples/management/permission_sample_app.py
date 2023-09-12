import logging

from descope import AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    management_key = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )
        name = "My Permission"

        try:
            logging.info("Going to create a new permission")
            descope_client.mgmt.permission.create(name, "Allowed to test :)")

        except AuthException as e:
            logging.info(f"Permission creation failed {e}")

        try:
            logging.info("Loading all permissions")
            permissions_resp = descope_client.mgmt.permission.load_all()
            permissions = permissions_resp["permissions"]
            for permission in permissions:
                logging.info(f"Search Found permission {permission}")

        except AuthException as e:
            logging.info(f"Permission load failed {e}")

        try:
            logging.info("Updating newly created permission")
            # update overrides all fields, must provide the entire entity
            # we mean to update.
            descope_client.mgmt.permission.update(
                name, new_name="My Updated Permission", description="New Description"
            )

        except AuthException as e:
            logging.info(f"Permission update failed {e}")

        try:
            logging.info("Deleting newly created permission")
            descope_client.mgmt.permission.delete("My Updated Permission")

        except AuthException as e:
            logging.info(f"Permission deletion failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
