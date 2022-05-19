import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import COOKIE_NAME, AuthClient, AuthException, DeliveryMethod  # noqa: E402

logging.basicConfig(level=logging.INFO)


def main():
    project_id = "299psneX92K3vpbqPMRCnbZKb27"
    public_key = """{"crv": "P-384", "key_ops": ["verify"], "kty": "EC", "x": "Zd7Unk3ijm3MKXt9vbHR02Y1zX-cpXu6H1_wXRtMl3e39TqeOJ3XnJCxSfE5vjMX", "y": "Cv8AgXWpMkMFWvLGhJ_Gsb8LmapAtEurnBsFI4CAG42yUGDfkZ_xjFXPbYssJl7U", "alg": "ES384", "use": "sig", "kid": "32b3da5277b142c7e24fdf0ef09e0919"}"""

    # signup_user_details = User(
    #    username="jhon", name="john", phone="972525555555", email="guyp@descope.com"
    # )

    # jwt_token = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjI5OXBzbmVYOTJLM3ZwYnFQTVJDbmJaS2IyNyIsInR5cCI6IkpXVCJ9.eyJleHAiOi01Njk3NDE5NDA0LCJpc3MiOiIyOTlwc25lWDkySzN2cGJxUE1SQ25iWktiMjciLCJzdWIiOiIyOUNHZTJ5cWVLUkxvV1Y5SFhTNmtacDJvRjkifQ.zqfbAzLcdxCZHW-bw5PbmPovrcIHWAYOFLqGvPDB7vUMG33w-5CcQtdVOiYX-CW5PBudtsSfkE1C3eiiqgWj4MUyKeK6oUWm6KRpaB5T58pxVxTa9OWcEBdT8oBW0Yit"

    try:
        auth_client = AuthClient(project_id=project_id, public_key=public_key)

        identifier = "guyp@descope.com"

        logging.info(
            "Going to signup new user.. expect an email to arrive with the new code.."
        )
        # auth_client.sign_up_otp(method=DeliveryMethod.EMAIL, identifier=identifier, user=signup_user_details)
        auth_client.sign_in_otp(method=DeliveryMethod.EMAIL, identifier=identifier)

        value = input("Please insert the code you received by email:\n")
        try:
            cookies = auth_client.verify_code(
                method=DeliveryMethod.EMAIL, identifier=identifier, code=value
            )
            logging.info("Code is valid")
            token = cookies.get(COOKIE_NAME)
        except AuthException:
            logging.info("Invalid code")
            raise

        try:
            logging.info("going to validate session..")
            auth_client.validate_session_request(token)
            logging.info("Session is valid and all is OK")
        except AuthException:
            logging.info("Session is not valid")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
