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
    project_id = ""

    try:
        auth_client = AuthClient(project_id=project_id)

        logging.info("Going to sign-in / sign-up...")
        email = input("Please insert email to sign in / sign-up:\n")
        auth_client.magiclink.sign_up_or_in(
            method=DeliveryMethod.EMAIL,
            identifier=email,
            uri="http://test.me",
        )

        token = input("Please insert the token you received by email:\n")
        try:
            jwt_response = auth_client.magiclink.verify(token=token)
            logging.info("Code is valid")
            session_token = jwt_response["jwts"].get(SESSION_COOKIE_NAME).get("jwt")
            refresh_token = (
                jwt_response["jwts"].get(REFRESH_SESSION_COOKIE_NAME).get("jwt")
            )
            logging.info(f"jwt_response: {jwt_response}")
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        try:
            logging.info("Going to logout after sign-in / sign-up")
            auth_client.logout(session_token, refresh_token)
            logging.info("User logged out after sign-in / sign-up")
        except AuthException as e:
            logging.info(f"Failed to logged after sign-in / sign-up, err: {e}")

        logging.info(
            "Going to sign in same user again..."
        )
        auth_client.magiclink.sign_in(
            method=DeliveryMethod.EMAIL, identifier=email, uri="http://test.me"
        )

        token = input("Please insert the code you received by email:\n")
        try:
            jwt_response = auth_client.magiclink.verify(token=token)
            logging.info("Code is valid")
            session_token_1 = jwt_response["jwts"].get(SESSION_COOKIE_NAME).get("jwt")
            refresh_token_1 = (
                jwt_response["jwts"].get(REFRESH_SESSION_COOKIE_NAME).get("jwt")
            )
            logging.info(f"jwt_response: {jwt_response}")
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        try:
            logging.info(f"going to validate session...{session_token_1}")
            claims = auth_client.validate_session_request(
                session_token_1, refresh_token_1
            )
            session_token_2 = claims.get(SESSION_COOKIE_NAME).get("jwt")
            logging.info("Session is valid and all is OK", session_token_2, refresh_token_1)
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            logging.info(f"Going to logout at the second time\nsession_token_2: {session_token_2}\nrefresh_token: {refresh_token_1}")
            auth_client.logout(session_token_2, refresh_token_1)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
