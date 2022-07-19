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
        user = {"name": "John", "phone": "+972111111111"}
        auth_client.sign_up_magiclink(
            method=DeliveryMethod.EMAIL,
            identifier=identifier,
            uri="http://test.me",
            user=user,
        )

        value = input("Please insert the code you received by email:\n")
        try:
            jwt_response = auth_client.verify_magiclink(code=value)
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
            logging.info("Going to logout")
            auth_client.logout(session_token, refresh_token)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

        logging.info(
            "Going to sign in same user again.. expect another email to arrive with the new link.."
        )
        auth_client.sign_in_magiclink(
            method=DeliveryMethod.EMAIL, identifier=identifier, uri="http://test.me"
        )

        value = input("Please insert the code you received by email:\n")
        try:
            jwt_response = auth_client.verify_magiclink(code=value)
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
            logging.info("going to validate session..")
            claims = auth_client.validate_session_request(
                session_token_1, refresh_token_1
            )
            session_token_2 = claims.get(SESSION_COOKIE_NAME).get("jwt")
            logging.info("Session is valid and all is OK")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            logging.info("Going to logout")
            auth_client.logout(session_token_2, refresh_token)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
