import logging

from descope import (
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
    AuthException,
    DescopeClient,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    try:
        descope_client = DescopeClient(project_id=project_id)

        logging.info("Going to signup using password...")
        email = input("Please insert email to signup with:\n")
        password = input("Please insert a password to signup with:\n")
        try:
            jwt_response = descope_client.password.sign_up(email, password)
            session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
            refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
        except AuthException as e:
            logging.info(f"Failed to sign up {e}")
            raise

        logging.info("Validating email address...")
        try:
            descope_client.magiclink.update_user_email(email, email, refresh_token)
        except AuthException as e:
            logging.info(f"Failed to sign up {e}")
            raise

        token = input(
            "Validation email send, please paste the token you received by email:\n"
        )
        try:
            jwt_response = descope_client.magiclink.verify(token)
            logging.info("Token is valid")
            session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
            refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
            logging.info(f"jwt_response: {jwt_response}")
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        logging.info("Going to reset password...")
        descope_client.password.send_reset(email)
        token = input(
            "Reset email send, please paste the token you received by email:\n"
        )
        try:
            jwt_response = descope_client.magiclink.verify(token)
            logging.info("Token is valid")
            session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
            refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
            logging.info(f"jwt_response: {jwt_response}")
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        new_password = input("Please insert a new password:\n")
        try:
            descope_client.password.update(email, new_password, refresh_token)
        except AuthException as e:
            logging.info(f"Unable to update password {e}")
            raise

        logging.info("Attempting to log in using the new password...")
        try:
            jwt_response = descope_client.password.sign_in(email, new_password)
            session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
            refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
            logging.info(f"jwt_response: {jwt_response}")
        except AuthException as e:
            logging.info(f"Failed to sign in {e}")
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
