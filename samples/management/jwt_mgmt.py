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
        user_login_id = "des@copeland.com"

        try:
            logging.info("Going to create a new user by sign up or in method")
            resp = descope_client.mgmt.jwt.sign_up_or_in(user_login_id)
            logging.info(f"Response: {resp}")

        except AuthException as e:
            logging.info(f"User SignUpOrIn failed {e}")

        try:
            logging.info("Searching for created user")
            resp = descope_client.mgmt.jwt.sign_in(user_login_id)
            logging.info(f"Response: {resp}")

        except AuthException as e:
            logging.info(f"User SignIn failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
