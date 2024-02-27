import logging

from descope import AccessKeyLoginOptions, AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    access_key = ""

    try:
        descope_client = DescopeClient(project_id=project_id)
        logging.info("Going to login by using access key ...")
        if not access_key:
            access_key = input("Please insert the access key\n")

        try:
            loc = AccessKeyLoginOptions(custom_claims={"k1": "v1"})
            jwt_response = descope_client.exchange_access_key(
                access_key=access_key, login_options=loc
            )
            logging.info("exchange access key successfully")
            logging.info(f"jwt_response: {jwt_response}")

            permission_name = "TestPermission"
            permission_presented = descope_client.validate_permissions(
                jwt_response, [permission_name]
            )
            logging.info(
                f"{permission_name} presented on the jwt: [{permission_presented}]"
            )
            role_name = "TestRole"
            role_presented = descope_client.validate_roles(jwt_response, [role_name])
            logging.info(f"{role_name} presented on the jwt: [{role_presented}]")
        except AuthException as e:
            logging.info(f"Failed to exchange access key {e}")
            raise

    except AuthException:
        raise


if __name__ == "__main__":
    main()
