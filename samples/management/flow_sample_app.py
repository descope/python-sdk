import logging

from descope import AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    management_key = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )
        name = "sign-up-or-in"

        try:
            logging.info("Going get 'sign-up-or-in' flow")
            res = descope_client.mgmt.flow.export_flow(name)

        except AuthException as e:
            logging.info(f"Export flow failed {e}")

        try:
            logging.info("Importing sign-up-or-in flow and change name")
            res["flow"]["name"] = "Importing from SDK"
            res = descope_client.mgmt.flow.import_flow(
                "sign-up-or-in", res["flow"], res["screens"]
            )

        except AuthException as e:
            logging.info(f"Importing flow failed {e}")

        try:
            logging.info("Going get the project theme")
            res = descope_client.mgmt.flow.import_theme()

        except AuthException as e:
            logging.info(f"Export theme failed {e}")

        try:
            logging.info("Importing theme back")
            res = descope_client.mgmt.flow.import_theme("sign-up-or-in", res)

        except AuthException as e:
            logging.info(f"Importing theme failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
