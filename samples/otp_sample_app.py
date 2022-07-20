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

        email = "asaf@descope.com" # input("Please insert email to sign in / sign-up:\n")

        logging.info(
            "Going to sign in new user.. expect an email to arrive with the new code.."
        )
        auth_client.otp.sign_in(method=DeliveryMethod.EMAIL, identifier=email)

        value = input("Please insert the code you received by email:\n")
        try:
            jwt_response = auth_client.otp.verify_code(
                method=DeliveryMethod.EMAIL, identifier=email, code=value
            )
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
            logging.info("going to validate session..")
            claims = auth_client.validate_session_request(session_token, refresh_token)
            logging.info("Session is valid and all is OK")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            logging.info("refreshing the session token..")
            claims = auth_client._auth_helper.refresh_token(refresh_token)
            logging.info(
                "going to revalidate the session with the newly refreshed token.."
            )

            new_session_token = claims.get(SESSION_COOKIE_NAME).get("jwt")
            claims = auth_client.validate_session_request(
                new_session_token, refresh_token
            )
            logging.info("Session is valid also for the refreshed token.")
        except AuthException as e:
            logging.info(f"Session is not valid for the refreshed token: {e}")

        try:
            auth_client.logout(refresh_token)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
