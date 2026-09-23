import logging

from descope import AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    project_id = ""
    app_id = ""  # The Federated (OIDC) App ID from the Descope console (app.descope.com/applications)

    try:
        descope_client = DescopeClient(project_id=project_id)

        logging.info("Building the sign-in redirect URL for an OIDC Federated App...")
        resp = descope_client.app.start(app_id, "https://my-app.com/callback")
        logging.info(f"app response: {resp}")

        # Redirect the browser to resp["url"]. Persist resp["state"] and
        # resp["code_verifier"] (e.g. in a server-side session) until the callback:
        #
        # code = ...  # from the "code" query param on the callback request
        # jwt_response = descope_client.app.exchange_token(
        #     app_id, code, code_verifier=resp["code_verifier"]
        # )
        # (jwt_response is the raw OIDC token shape: access_token, id_token, ... -
        # not this SDK's usual sessionJwt/refreshJwt shape. Add client_secret= if the app
        # is a confidential OAuth client.)

    except AuthException:
        raise


if __name__ == "__main__":
    main()
