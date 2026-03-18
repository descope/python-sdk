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
        name = "My Role"

        try:
            logging.info("Going to create a new role")
            descope_client.mgmt.role.create(
                name,
                "Allowed to test :)",
                permission_names=["SSO Admin"],
                default=False,  # Optional, marks this role as default role
                private=False,  # Optional, marks this role as private role
            )

        except AuthException as e:
            logging.info(f"Role creation failed {e}")

        try:
            logging.info("Going to create a batch of roles")
            descope_client.mgmt.role.create_batch(
                [
                    {
                        "name": "Batch Role 1",
                        "description": "First batch role",
                        "permissionNames": ["SSO Admin"],
                    },
                    {
                        "name": "Batch Role 2",
                        "description": "Second batch role",
                        "default": True,
                    },
                ]
            )

        except AuthException as e:
            logging.info(f"Role batch creation failed {e}")

        try:
            logging.info("Loading all roles")
            roles_resp = descope_client.mgmt.role.load_all()
            roles = roles_resp["roles"]
            for role in roles:
                logging.info(f"Search Found role {role}")

        except AuthException as e:
            logging.info(f"Role load failed {e}")

        try:
            logging.info("Searching roles by tenant and name filters")
            roles_resp = descope_client.mgmt.role.search(
                tenant_ids=["t1", "t2"],
                role_names=["My Role"],
            )
            roles = roles_resp["roles"]
            for role in roles:
                logging.info(f"Search Found role {role}")

        except AuthException as e:
            logging.info(f"Role search failed {e}")

        try:
            logging.info("Updating newly created role")
            # update overrides all fields, must provide the entire entity
            # we mean to update.
            descope_client.mgmt.role.update(
                name,
                new_name="My Updated Role",
                description="New Description",
                permission_names=["User Admin"],
                default=False,  # Optional, marks this role as default role
                private=False,  # Optional, marks this role as private role
            )

        except AuthException as e:
            logging.info(f"Role update failed {e}")

        try:
            logging.info("Updating a batch of roles")
            descope_client.mgmt.role.update_batch(
                [
                    {
                        "name": "Batch Role 1",
                        "newName": "Updated Batch Role 1",
                        "description": "Updated description",
                        "permissionNames": ["User Admin"],
                    },
                ]
            )

        except AuthException as e:
            logging.info(f"Role batch update failed {e}")

        try:
            logging.info("Deleting newly created role")
            descope_client.mgmt.role.delete("My Updated Role")

        except AuthException as e:
            logging.info(f"Role deletion failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
