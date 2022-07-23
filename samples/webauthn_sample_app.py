import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import AuthClient, AuthException  # noqa: E402

logging.basicConfig(level=logging.INFO)


def virtualwebauthn(response: str):
    pass
    # Virtual webauthn
    # ParseAttestationOptions
    # response["publicKey"]
    # if response["publicKey"]["challenge"] == "":
    #     raise
    # c = response["publicKey"]["challenge"].decode('ascii')
    # {
    #     "challenge": c
    # }
    # CreateAttestationResponse


def main():
    project_id = ""
    email = "dummy@dummy.com"

    try:
        auth_client = AuthClient(project_id=project_id)

        logging.info("Going to sign up using WebauthN ...")
        response = auth_client.webauthn.sign_up_start(email, {"name": "dummy"})

        attestationOptions = virtualwebauthn()

        auth_client.webauthn.sign_up_finish(
            response["transactionId"], attestationOptions
        )

    except AuthException:
        raise


if __name__ == "__main__":
    main()
