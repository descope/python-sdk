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
        key_id = ""

        try:
            logging.info("Going to create a new access key")
            access_key_resp = descope_client.mgmt.access_key.create(
                name="key-name", expire_time=1677844931
            )
            access_key = access_key_resp["key"]
            key_id = access_key["id"]
            logging.info(f"Create: created access key {access_key}")

        except AuthException as e:
            logging.info(f"Access key creation failed {e}")

        try:
            logging.info("Searching for created access key")
            access_key_resp = descope_client.mgmt.access_key.load(key_id)
            access_key = access_key_resp["key"]
            logging.info(f"Load: found access key {access_key}")

        except AuthException as e:
            logging.info(f"Access key load failed {e}")

        try:
            logging.info("Searching all access keys")
            users_resp = descope_client.mgmt.access_key.search_all_access_keys()
            access_keys = users_resp["keys"]
            for key in access_keys:
                logging.info(f"Search Found access key {key}")

        except AuthException as e:
            logging.info(f"Access key load failed {e}")

        try:
            logging.info("Updating newly created access key")
            # update overrides all fields, must provide the entire entity
            # we mean to update.
            descope_client.mgmt.access_key.update(key_id, "New key name")

        except AuthException as e:
            logging.info(f"Access key update failed {e}")

        try:
            logging.info("Deactivating newly created access key")
            descope_client.mgmt.access_key.deactivate(key_id)

        except AuthException as e:
            logging.info(f"Access key deactivate failed {e}")

        try:
            logging.info("Activating newly created access key")
            descope_client.mgmt.access_key.activate(key_id)

        except AuthException as e:
            logging.info(f"Access key activate failed {e}")

        try:
            logging.info("Deleting newly created access key")
            descope_client.mgmt.access_key.delete(key_id)

        except AuthException as e:
            logging.info(f"Access key deletion failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
