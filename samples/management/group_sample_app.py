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
        tenant_id = ""  # tenant id to search groups in

        try:
            logging.info("Going to load all groups for tenant")
            groups_resp = descope_client.mgmt.group.load_all_groups(tenant_id=tenant_id)
            for group in groups_resp:
                logging.info(f"Search Found group {group}")
            login_id = groups_resp[0]["members"][0]["loginId"]
            user_id = groups_resp[0]["members"][0]["userId"]
            group_id = groups_resp[0]["id"]
        except AuthException as e:
            logging.info(f"Groups load failed {e}")

        try:
            logging.info("Going to load all groups for members - using login ID")
            groups_resp = descope_client.mgmt.group.load_all_groups_for_members(
                tenant_id=tenant_id,
                login_ids=[login_id],
            )
            for group in groups_resp:
                logging.info(f"Search Found group {group}")
        except AuthException as e:
            logging.info(f"Groups load failed {e}")

        try:
            logging.info("Going to load all groups for members - using user IDs")
            groups_resp = descope_client.mgmt.group.load_all_groups_for_members(
                tenant_id=tenant_id,
                user_ids=[user_id],
            )
            for group in groups_resp:
                logging.info(f"Search Found group {group}")
        except AuthException as e:
            logging.info(f"Groups load failed {e}")

        try:
            logging.info("Going to load all members for group")
            groups_resp = descope_client.mgmt.group.load_all_group_members(
                tenant_id=tenant_id,
                group_id=group_id,
            )
            for group in groups_resp:
                logging.info(f"Search Found group {group}")
        except AuthException as e:
            logging.info(f"Groups load failed {e}")
    except AuthException:
        raise


if __name__ == "__main__":
    main()
