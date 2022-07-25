import json
import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import (  # noqa: E402
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    AuthException,
    DeliveryMethod,
    DescopeClient,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""

    try:
        descope_client = DescopeClient(project_id=project_id)

        logging.info("Going to sign in using TOTP ...")
        email = input("Please insert your identifier:\n")

        signup = input("Do you want to sign up via TOTP? (yes/y):\n")
        if signup == "yes" or signup == "y":
            totp_info = descope_client.totp.sign_up(email)
            logging.info("=== use this info in Authenticator app ===")
            logging.info(json.dumps(totp_info, indent=2, sort_keys=True))
            logging.info("=========================================")
        else:
            register = input(
                "Do you need to register an authenticator to an existing account? (yes/y):\n"
            )
            if register == "yes" or register == "y":
                logging.info("Please sing in via OTP...")
                descope_client.otp.sign_up_or_in(DeliveryMethod.EMAIL, email)

                code = input("Please insert the code you received by email:\n")

                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.EMAIL, email, code
                )
                refresh_token = (
                    jwt_response["jwts"].get(REFRESH_SESSION_COOKIE_NAME).get("jwt")
                )
                totp_info = descope_client.totp.update_user(email, refresh_token)
                logging.info("=== use this info in Authenticator app ===")
                logging.info(json.dumps(totp_info, indent=2, sort_keys=True))
                logging.info("=========================================")

        code = input("Please insert code from Authenticator:\n")

        jwt_response = descope_client.totp.sign_in_code(
            identifier=email,
            code=code,
        )

        logging.info("Code is valid")

        session_token = jwt_response["jwts"].get(SESSION_COOKIE_NAME).get("jwt")
        refresh_token = jwt_response["jwts"].get(REFRESH_SESSION_COOKIE_NAME).get("jwt")

        # validate session
        try:
            logging.info("going to validate session...")
            claims = descope_client.validate_session_request(
                session_token, refresh_token
            )
            logging.info(f"Session is valid and all is OK, claims: {claims}")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        # logout
        try:
            logging.info("Going to logout...")
            descope_client.logout(refresh_token)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged, err: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
