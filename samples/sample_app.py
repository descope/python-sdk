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
    public_key = (
        None  # will automatically fetch all public keys related to the project_id
    )

    try:
        auth_client = AuthClient(project_id=project_id, public_key=public_key)

        logging.info(
            "Going to signin new user.. expect an email to arrive with the new code.."
        )
        auth_client.sign_in_otp(method=DeliveryMethod.EMAIL, identifier=identifier)

        value = input("Please insert the code you received by email:\n")
        try:
            cookies = auth_client.verify_code(
                method=DeliveryMethod.EMAIL, identifier=identifier, code=value
            )
            logging.info("Code is valid")
            token = cookies.get(SESSION_COOKIE_NAME, "")
            refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME, "")
            logging.info(f"token: {token} \n refresh token: {refresh_token}")
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        try:
            logging.info("going to validate session..")
            token = auth_client.validate_session_request(token, refresh_token)
            logging.info("Session is valid and all is OK")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            logging.info("refreshing the session token..")
            new_session_token = auth_client.refresh_token(token, refresh_token)
            logging.info(
                "going to revalidate the session with the newly refreshed token.."
            )
            token = auth_client.validate_session_request(
                new_session_token, refresh_token
            )
            logging.info("Session is valid also for the refreshed token.")
        except AuthException as e:
            logging.info(f"Session is not valid for the refreshed token: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
