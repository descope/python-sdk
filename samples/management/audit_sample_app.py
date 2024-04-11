import logging
import sys
from datetime import datetime

from descope import AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    # Either specify here or read from env
    project_id = ""
    management_key = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )
        try:
            logging.info("Going to create audit event")
            descope_client.mgmt.audit.create_event(
                action="pencil.created",
                user_id="user-id",
                actor_id="actor-id",
                tenant_id="tenant-id",
                type="info",
                data={"some": "data"},
            )
            logging.info("Create: created audit event")

        except AuthException as e:
            logging.info(f"Audit event creation failed {e}")

        try:
            logging.info("Going to search audit")
            text = None
            if len(sys.argv) > 1:
                text = sys.argv[1]
            from_ts = None
            if len(sys.argv) > 2:
                from_ts = datetime.fromisoformat(sys.argv[2])
            logging.info(descope_client.mgmt.audit.search(text=text, from_ts=from_ts))

        except AuthException as e:
            logging.info(f"Audit search failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
