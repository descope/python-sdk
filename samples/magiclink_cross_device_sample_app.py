import logging
import os
import sys
from threading import Thread
from time import sleep

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import (  # noqa: E402
    REFRESH_SESSION_TOKEN_NAME,
    AuthException,
    DeliveryMethod,
    DescopeClient,
)

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""

    try:
        descope_client = DescopeClient(project_id=project_id)

        def verify():
            token = input("Please insert the token you received by email:\n")
            try:
                descope_client.magiclink.verify(token=token)
                logging.info("Code is valid")
            except AuthException as e:
                logging.info(f"Invalid code {e}")
                raise

        logging.info("Going to signup / signin using Magic Link ...")
        email = input("Please insert email to signup / signin:\n")
        resp = descope_client.magiclink.sign_up_or_in_cross_device(
            method=DeliveryMethod.EMAIL,
            identifier=email,
            uri="http://test.me",
        )

        pending_ref = resp["pendingRef"]
        done = False

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
                jwt_response = descope_client.magiclink.get_session(pending_ref)
                done = True
            except AuthException as e:
                if e.status_code != 401:
                    logging.info(f"Failed pending session, err: {e}")
                    done = True

        if jwt_response:
            refresh_token = jwt_response.get(REFRESH_SESSION_TOKEN_NAME).get("jwt")
            descope_client.logout(refresh_token)
            logging.info("User logged out")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
