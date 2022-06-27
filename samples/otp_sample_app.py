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
    identifier = "dummy@dummy.com"
    project_id = ""
    try:
        auth_client = AuthClient(project_id=project_id)

        logging.info(
            "Going to signin new user.. expect an email to arrive with the new code.."
        )
        auth_client.sign_in_otp(method=DeliveryMethod.EMAIL, identifier=identifier)

        value = input("Please insert the code you received by email:\n")
        try:
            claims, tokens = auth_client.verify_code(
                method=DeliveryMethod.EMAIL, identifier=identifier, code=value
            )
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
            logging.info("going to validate session..")
            claims, tokens = auth_client.validate_session_request(
                session_token, refresh_token
            )
            session_token = tokens.get(SESSION_COOKIE_NAME, "")
            refresh_token = tokens.get(REFRESH_SESSION_COOKIE_NAME, "")
            logging.info("Session is valid and all is OK")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            logging.info("refreshing the session token..")
            new_session_token = auth_client.refresh_token(session_token, refresh_token)
            logging.info(
                "going to revalidate the session with the newly refreshed token.."
            )
            claims, tokens = auth_client.validate_session_request(
                new_session_token, refresh_token
            )
            logging.info("Session is valid also for the refreshed token.")
        except AuthException as e:
            logging.info(f"Session is not valid for the refreshed token: {e}")

        try:
            auth_client.logout(new_session_token, refresh_token)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()