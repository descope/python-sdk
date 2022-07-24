import logging
import os
import sys
from time import sleep
from threading import Thread

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import (  # noqa: E402
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    AuthClient,
    AuthException,
    DeliveryMethod,
)

logging.basicConfig(level=logging.INFO)

def main():
    project_id = ""
    
    try:
        auth_client = AuthClient(project_id=project_id)


        def verify():
            token = input("Please insert the token you received by email:\n")
            try:
                auth_client.magiclink.verify(token=token)
                logging.info("Code is valid")
            except AuthException as e:
                logging.info(f"Invalid code {e}")
                raise
            
        logging.info("Going to signup / signin using Magic Link ...")
        email = input("Please insert email to signup / signin:\n")
        resp = auth_client.magiclink.sign_up_or_in_cross_device(
            method=DeliveryMethod.EMAIL,
            identifier=email,
            uri="http://test.me",
        )
        
        pending_ref = resp["pendingRef"]
        done = False
        authenticated = False
        
        # open thread to get input
        new_thread = Thread(target=verify)
        new_thread.start()
        
        i = 0
        while not done:
            try:
                i = i + 1
                sys.stdout.write(f"\r Sleeping {i}...")
                sys.stdout.flush()
                sleep(4)
                jwt_response = auth_client.magiclink.get_session(pending_ref)
                done = True
                authenticated = True
            except AuthException as e:
                if e.status_code != 401:
                    logging.info(f"Failed pending session, err: {e}")
                    authenticated = False
                    done = True
                    
        if jwt_response:
            refresh_token = jwt_response["jwts"].get(REFRESH_SESSION_COOKIE_NAME).get("jwt")
            auth_client.logout(refresh_token)
            logging.info("User logged out")
        
    except AuthException:
        raise


if __name__ == "__main__":
    main()
