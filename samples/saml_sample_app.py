import logging
import os
import sys

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import AuthClient, AuthException  # noqa: E402

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    tenant_id = ""

    try:
        auth_client = AuthClient(project_id=project_id)

        logging.info("Going to login with SAML auth method ...")
        resp = auth_client.saml.start(tenant_id, "https://www.google.com")
        logging.info(f"saml response: {resp}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
