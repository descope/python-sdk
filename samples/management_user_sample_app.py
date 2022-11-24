import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import AuthException, DescopeClient  # noqa: E402

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    mgmt_key = ""

    try:
        descope_client = DescopeClient(project_id=project_id)
        user_identifier = "des@copeland.com"

        try:
            logging.info("Going to create a new user")
            descope_client.mgmt.user.create(mgmt_key, user_identifier)

        except AuthException as e:
            logging.info(f"User creation failed {e}")

        try:
            logging.info("Updating newly created user")
            # update overrides all fields, must provide the entire entity
            # we mean to update.
            descope_client.mgmt.user.update(
                mgmt_key, user_identifier, display_name="Desmond Copeland"
            )

        except AuthException as e:
            logging.info(f"User update failed {e}")

        try:
            logging.info("Deleting newly created tenant")
            descope_client.mgmt.user.delete(mgmt_key, user_identifier)

        except AuthException as e:
            logging.info(f"User deletion failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
