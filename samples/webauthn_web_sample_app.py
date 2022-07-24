import os
import sys

from flask import Flask, jsonify, render_template, request

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import DescopeClient  # noqa: E402

APP = Flask(__name__)

PROJECT_ID = ""

# init the DescopeClient
descope_client = DescopeClient(PROJECT_ID)

# Note: Use "https://localhost:443 in the browser (and not 127.0.0.1)


class Error(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(Error)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# This doesn't need authentication
@APP.route("/")
def home():
    return render_template("webauthn_demo.html")


@APP.route("/webauthn/signup/start", methods=["POST"])
def webauthn_signup_start():
    data = request.get_json()
    response = descope_client.webauthn.sign_up_start(
        data["externalID"], {"name": data["displayName"]}
    )
    return response


@APP.route("/webauthn/signup/finish", methods=["POST"])
def webauthn_signup_finish():
    data = request.get_json()
    response = descope_client.webauthn.sign_up_finish(
        data["transactionId"], data["response"]
    )
    print(response)
    return response


@APP.route("/webauthn/signin/start", methods=["POST"])
def webauthn_signin_start():
    id = request.args.get("id")
    response = descope_client.webauthn.sign_in_start(id)
    return response


@APP.route("/webauthn/signin/finish", methods=["POST"])
def webauthn_signin_finish():
    data = request.get_json()
    response = descope_client.webauthn.sign_in_finish(
        data["transactionId"], data["response"]
    )
    print(response)
    return response


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=443, ssl_context="adhoc")
