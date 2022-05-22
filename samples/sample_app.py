import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import (  # noqa: E402
    SESSION_COOKIE_NAME,
    AuthClient,
    AuthException,
    DeliveryMethod,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = "299psneX92K3vpbqPMRCnbZKb27"
    public_key = """{"crv": "P-384", "key_ops": ["verify"], "kty": "EC", "x": "Zd7Unk3ijm3MKXt9vbHR02Y1zX-cpXu6H1_wXRtMl3e39TqeOJ3XnJCxSfE5vjMX", "y": "Cv8AgXWpMkMFWvLGhJ_Gsb8LmapAtEurnBsFI4CAG42yUGDfkZ_xjFXPbYssJl7U", "alg": "ES384", "use": "sig", "kid": "32b3da5277b142c7e24fdf0ef09e0919"}"""
    identifier = "dummy@dummy.com"

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
            token = cookies.get(SESSION_COOKIE_NAME)
        except AuthException as e:
            logging.info(f"Invalid code {e}")
            raise

        try:
            logging.info("going to validate session..")
            auth_client.validate_session_request(token)
            logging.info("Session is valid and all is OK")
        except AuthException as e:
            logging.info(f"Session is not valid {e}")

        try:
            old_public_key = auth_client.public_key
            # fetch and load the public key associated with this project (by kid)
            auth_client._fetch_public_key(project_id)
            if old_public_key != auth_client.public_key:
                logging.info("new public key fetched successfully")
            else:
                logging.info("failed to fetch new public_key")
        except AuthException as e:
            logging.info(f"failed to fetch public key for this project {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
