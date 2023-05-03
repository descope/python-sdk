from decorators.flask_decorators import (  # noqa: E402;
    descope_full_login,
    descope_logout,
    descope_validate_auth,
)
from flask import Flask, Response

from descope import DescopeClient  # noqa: E402

APP = Flask(__name__)
PROJECT_ID = ""  # Can be set also by environment variable

# init the DescopeClient
descope_client = DescopeClient(PROJECT_ID)


@APP.route("/login", methods=["GET"])
@descope_full_login(
    project_id=PROJECT_ID,
    flow_id="sign-up-or-in",
    success_redirect_url="http://dev.localhost:9010/private",
)
def login():
    # Nothing to do! this is the MAGIC!
    pass


# This needs authentication
@APP.route("/private")
@descope_validate_auth(
    descope_client
)  # Can add permissions=["Perm 1"], roles=["Role 1"], tenant="t1" conditions
def private():
    return Response("<h1>Restricted page, authentication needed.</h1>")


@APP.route("/logout")
@descope_logout(descope_client)
def logout():
    return Response("<h1>Goodbye, logged out.</h1>")


# This doesn't need authentication
@APP.route("/")
def home():
    return Response("<h1>Hello, public page!</h1>")


if __name__ == "__main__":
    APP.run(
        host="dev.localhost", port=9010
    )  # cannot run on localhost as cookie will not work (just add it to your /etc/hosts file)
