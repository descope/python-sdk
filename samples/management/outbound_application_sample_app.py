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
        outbound_app_id = ""

        # CREATE OUTBOUND APPLICATION

        try:
            logging.info("Going to create a new outbound application")
            resp = descope_client.mgmt.outbound_application.create_application(
                "My first outbound application",
                description="This is a test outbound application",
                client_secret="shhh..",
            )
            outbound_app_id = resp["app"]["id"]
            logging.info(f"Outbound application creation response: {resp}")

        except AuthException as e:
            logging.info(f"Outbound application creation failed {e}")

        # LOAD OUTBOUND APPLICATION

        try:
            logging.info("Loading outbound application by id")
            outbound_app_resp = (
                descope_client.mgmt.outbound_application.load_application(
                    outbound_app_id
                )
            )
            logging.info(f"Found outbound application {outbound_app_resp}")

        except AuthException as e:
            logging.info(f"Outbound application load failed {e}")

        # LOAD ALL OUTBOUND APPLICATIONS

        try:
            logging.info("Loading all outbound applications")
            outbound_app_resp = (
                descope_client.mgmt.outbound_application.load_all_applications()
            )
            apps = outbound_app_resp["apps"]
            for app in apps:
                logging.info(f"LoadAll Found outbound application: {app}")

        except AuthException as e:
            logging.info(f"Outbound application load all failed {e}")

        # UPDATE OUTBOUND APPLICATION

        try:
            logging.info("Going to update the outbound application")
            descope_client.mgmt.outbound_application.update_application(
                outbound_app_id,
                "Updated outbound application name",
                description="Updated description",
                logo="https://example.com/logo.png",
                client_secret="new-secret",
            )
            logging.info("Outbound application updated successfully")

        except AuthException as e:
            logging.info(f"Outbound application update failed {e}")

        # FETCH TOKEN BY SCOPES

        try:
            logging.info("Going to fetch token by scopes")
            token_resp = descope_client.mgmt.outbound_application.fetch_token_by_scopes(
                outbound_app_id,
                "user123",
                ["read", "write"],
                options={"refreshToken": True},
                tenant_id="tenant456",
            )
            logging.info(f"Token fetch response: {token_resp}")

        except AuthException as e:
            logging.info(f"Token fetch by scopes failed {e}")

        # FETCH TOKEN

        try:
            logging.info("Going to fetch token")
            token_resp = descope_client.mgmt.outbound_application.fetch_token(
                outbound_app_id,
                "user123",
                tenant_id="tenant456",
                options={"forceRefresh": True},
            )
            logging.info(f"Token fetch response: {token_resp}")

        except AuthException as e:
            logging.info(f"Token fetch failed {e}")

        # FETCH TENANT TOKEN BY SCOPES

        try:
            logging.info("Going to fetch tenant token by scopes")
            token_resp = (
                descope_client.mgmt.outbound_application.fetch_tenant_token_by_scopes(
                    outbound_app_id,
                    "tenant456",
                    ["read", "write"],
                    options={"refreshToken": True},
                )
            )
            logging.info(f"Tenant token fetch response: {token_resp}")

        except AuthException as e:
            logging.info(f"Tenant token fetch by scopes failed {e}")

        # FETCH TENANT TOKEN

        try:
            logging.info("Going to fetch tenant token")
            token_resp = descope_client.mgmt.outbound_application.fetch_tenant_token(
                outbound_app_id,
                "tenant456",
                options={"forceRefresh": True},
            )
            logging.info(f"Tenant token fetch response: {token_resp}")

        except AuthException as e:
            logging.info(f"Tenant token fetch failed {e}")

        # DELETE OUTBOUND APPLICATION

        try:
            logging.info("Going to delete the outbound application")
            descope_client.mgmt.outbound_application.delete_application(outbound_app_id)
            logging.info("Outbound application deleted successfully")

        except AuthException as e:
            logging.info(f"Outbound application deletion failed {e}")

    except AuthException as e:
        logging.info(f"Failed to initialize client: {e}")


if __name__ == "__main__":
    main()
