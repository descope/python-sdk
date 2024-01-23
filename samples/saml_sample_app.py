import logging

from descope import AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    project_id = "P2PD8H2nZbPk5cSJfChsc00ZCi0w"
    tenant_id = "descope.com"

    try:
        descope_client = DescopeClient(project_id=project_id)

        logging.info("Going to login with SSO auth method ...")
        resp = descope_client.sso.start(tenant_id, "https://www.google.com")
        logging.info(f"sso response: {resp}")
        
    except AuthException:
        raise


if __name__ == "__main__":
    main()
