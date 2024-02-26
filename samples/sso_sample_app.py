import logging

from descope import AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    tenant_id = ""

    try:
        descope_client = DescopeClient(project_id=project_id)

        logging.info(
            "Going to login with SSO auth method (saml/oidc based on tenant settings)..."
        )
        resp = descope_client.sso.start(tenant_id, "https://www.google.com")
        logging.info(f"sso response: {resp}")

        # Note: after redirecting to the login page (result of the above call) we will get a code
        # that should be exchanged back by using the following call that will return the user JWTs:

        # resp = descope_client.sso.exchange_token(code)

    except AuthException:
        raise


if __name__ == "__main__":
    main()
