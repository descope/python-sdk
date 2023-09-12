import logging

from descope import (
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
    AuthException,
    DeliveryMethod,
    DescopeClient,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    try:
        descope_client = DescopeClient(project_id=project_id)

        logging.info("Going to signup or in using OTP...")
        email = input("Please insert email to signup or in:\n")
        masked_email = descope_client.otp.sign_up_or_in(
            method=DeliveryMethod.EMAIL, login_id=email
        )

        value = input(
            f"Please insert the code you received by email to {masked_email}:\n"
        )
        try:
            jwt_response = descope_client.otp.verify_code(
                method=DeliveryMethod.EMAIL, login_id=email, code=value
            )
            logging.info("Code is valid")
            session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
            refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
            logging.info(f"jwt_response: {jwt_response}")
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        try:
            logging.info("going to validate session..")
            descope_client.validate_session(session_token)
            logging.info("Session is valid and all is OK")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            logging.info("refreshing the session token..")
            claims = descope_client.refresh_session(refresh_token)
            logging.info(
                "going to revalidate the session with the newly refreshed token.."
            )

            new_session_token = claims.get(SESSION_TOKEN_NAME).get("jwt")
            descope_client.validate_and_refresh_session(
                new_session_token, refresh_token
            )
            logging.info("Session is valid also for the refreshed token.")
        except AuthException as e:
            logging.info(f"Session is not valid for the refreshed token: {e}")

        try:
            descope_client.logout(refresh_token)
            logging.info("User logged out")
        except AuthException as e:
            logging.info(f"Failed to logged out user, err: {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
