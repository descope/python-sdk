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
)

logging.basicConfig(level=logging.INFO)

def main():
    project_id = ""
    try:
        auth_client = AuthClient(project_id=project_id)

        logging.info("Going to login with Oauth auth method ...")
        resp = auth_client.oauth.start("facebook", "www.google.com")
        logging.info(f"oauth response: {resp}")
        
        code = input("Please insert the code you received by email:\n")

        
        jwt_response = auth_client.oauth.exchange_token(code)
        logging.info(f"oauth code valid")
        refresh_token = jwt_response["jwts"].get(REFRESH_SESSION_COOKIE_NAME).get("jwt")
        auth_client.logout(refresh_token)
        logging.info("User logged out")
    
    except AuthException as e:
        logging.info(f"Failed to start oauth: {e}")


if __name__ == "__main__":
    main()
