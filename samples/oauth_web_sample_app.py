from flask import Flask, jsonify

from descope import DescopeClient

from .decorators.flask_decorators import (
    descope_logout,
    descope_oauth,
    descope_validate_auth,
)

APP = Flask(__name__)

PROJECT_ID = ""

# init the DescopeClient
descope_client = DescopeClient(PROJECT_ID)


class Error(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(Error)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# This needs authentication
@APP.route("/api/private")
@descope_validate_auth(descope_client)
def private():
    response = "This is a private API and you must be authenticated to see this"
    return jsonify(message=response)


@APP.route("/api/logout")
@descope_logout(descope_client)
def logout():
    response = "Logged out"
    return jsonify(message=response)


@APP.route("/api/oauth", methods=["GET"])
@descope_oauth(descope_client)
def oauth(*args, **kwargs):
    pass


# This doesn't need authentication
@APP.route("/")
def home():
    return "OK"


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=9000)
