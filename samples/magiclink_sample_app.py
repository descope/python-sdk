import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import (  # noqa: E402
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    AuthClient,
    AuthException,
    DeliveryMethod,
)

logging.basicConfig(level=logging.INFO)


def main():
    identifier = "test@me.com"
    project_id = ""

    try:
        auth_client = AuthClient(project_id=project_id)

        logging.info(
            "Going to signup a new user.. expect an email to arrive with the new link.."
        )
        auth_client.sign_up_magiclink(method=DeliveryMethod.EMAIL, identifier=identifier, uri="http://test.me")

        value = input("Please insert the code you received by email:\n")
        try:
            claims, tokens = auth_client.verify_magiclink(code=value)
            logging.info("Code is valid")
            session_token = tokens.get(SESSION_COOKIE_NAME, "")
            refresh_token = tokens.get(REFRESH_SESSION_COOKIE_NAME, "")
            logging.info(
                f"session token: {session_token} \n refresh token: {refresh_token} claims: {claims}"
            )
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        try:
            logging.info("Going to logout")
            auth_client.logout(session_token, refresh_token)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

        logging.info(
            "Going to signin same user again.. expect another email to arrive with the new link.."
        )
        auth_client.sign_in_magiclink(method=DeliveryMethod.EMAIL, identifier=identifier, uri="http://test.me")

        value = input("Please insert the code you received by email:\n")
        try:
            claims, tokens = auth_client.verify_magiclink(code=value)
            logging.info("Code is valid")
            session_token_1 = tokens.get(SESSION_COOKIE_NAME, "")
            refresh_token_1 = tokens.get(REFRESH_SESSION_COOKIE_NAME, "")
            logging.info(
                f"session token: {session_token_1} \n refresh token: {refresh_token_1} claims: {claims}"
            )
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        try:
            logging.info("going to validate session..")
            claims, tokens = auth_client.validate_session_request(
                session_token, refresh_token
            )
            session_token_2 = tokens.get(SESSION_COOKIE_NAME, "")
            refresh_token_2 = tokens.get(REFRESH_SESSION_COOKIE_NAME, "")
            logging.info("Session is valid and all is OK")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            logging.info("Going to logout")
            auth_client.logout(session_token_2, refresh_token_2)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
