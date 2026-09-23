"""
Homegrown first factor + Descope for MFA-only, via a Federated OIDC App.

The pattern:
  1. Your own backend authenticates the first factor however it always has (this sample
     fakes it with a hardcoded check - swap in your real logic).
  2. On success, call app.start(app_id, return_url, login_hint=<the user you just
     identified>) and redirect the browser to the result. This sample assumes the app's
     console-configured default flow has already been edited to be MFA-only (e.g. a
     magic-link challenge) - if yours still runs a full sign-up-or-in flow, either edit it in
     place via the console's Flow editor, or pass flow=<your MFA flow's ID> here to override
     it per-call instead.
  3. Descope's login page uses login_hint (forwarded as oidc_login_hint) to know who it's
     validating, runs just that flow's challenge, and redirects back with a code.
  4. Exchange the code for tokens. These are raw OIDC tokens (access_token/id_token/...),
     not this SDK's usual sessionJwt/refreshJwt - decide what your app does with them (e.g.
     treat a successful exchange as proof MFA passed, and mint/extend your own app's session
     accordingly).

Run:
    PROJECT_ID=... APP_ID=... CLIENT_SECRET=... python app_oidc_mfa_sample_app.py
Then open http://127.0.0.1:5000/ in a browser.

CLIENT_SECRET is only needed if the app is a confidential OAuth client (check its OIDC
settings in the console - a public/unspecified client doesn't need it, PKCE alone covers it).
CALLBACK_URL defaults to http://127.0.0.1:5000/callback; override it if the app's console
config registers a different redirect URI.
"""

import os

from flask import Flask, redirect, request, session
from markupsafe import escape

from descope import AuthException, DescopeClient

PROJECT_ID = os.environ["PROJECT_ID"]
APP_ID = os.environ["APP_ID"]
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")  # only needed for a confidential client
# Must match a redirect URI registered on the app in the console (or the app's redirect_uri
# validation may reject it at exchange time even though the initial redirect still succeeds).
CALLBACK_URL = os.environ.get("CALLBACK_URL", "http://127.0.0.1:5000/callback")

# Swap for a real user store - this sample fakes the "homegrown first factor" entirely.
FAKE_USER_DB = {"user@example.com": "password123"}

APP = Flask(__name__)
APP.secret_key = os.urandom(32)  # dev-only; use a stable, secret key in production

descope_client = DescopeClient(project_id=PROJECT_ID)


@APP.route("/")
def index():
    return """
        <h2>Step 1: Your homegrown login</h2>
        <form method="post" action="/login">
            <input name="email" placeholder="email" value="user@example.com">
            <input name="password" type="password" placeholder="password" value="password123">
            <button type="submit">Log in</button>
        </form>
    """


@APP.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    # --- your real first-factor check goes here ---
    if FAKE_USER_DB.get(email) != password:
        return "Invalid credentials", 401
    # ------------------------------------------------

    try:
        resp = descope_client.app.start(
            APP_ID,
            CALLBACK_URL,
            login_hint=email,
            # No `flow` override here: the app's console-configured default flow already IS
            # the MFA-only flow (edited in place, same flow ID). Pass flow=<your MFA flow's
            # ID> explicitly instead, if you'd rather override per-call than change the app's
            # default.
        )
    except AuthException:
        return "Failed to start MFA", 500

    # Stash what exchange_token will need - this is a redirect, so it can't carry state itself
    session["code_verifier"] = resp["code_verifier"]
    session["expected_state"] = resp["state"]
    session["email"] = email

    return redirect(resp["url"])


@APP.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        safe_error = escape(error)
        safe_error_description = escape(request.args.get("error_description", ""))
        return f"MFA failed: {safe_error} - {safe_error_description}", 401
    if not code or state != session.get("expected_state"):
        return "Invalid or missing callback params", 400

    try:
        tokens = descope_client.app.exchange_token(
            APP_ID,
            code,
            code_verifier=session.get("code_verifier"),
            client_secret=CLIENT_SECRET,
            redirect_uri=CALLBACK_URL,
        )
    except AuthException:
        return "MFA exchange failed", 401

    # tokens is the raw OIDC shape: access_token, id_token, refresh_token, expires_in, scope.
    # Treating a successful exchange as "MFA passed" - wire this into your own session logic
    # as needed.
    return f"""
        <h2>MFA complete for {session.get('email')}</h2>
        <p>id_token (truncated): {tokens.get('id_token', '')[:40]}...</p>
        <p>expires_in: {tokens.get('expires_in')}s</p>
    """


if __name__ == "__main__":
    APP.run(port=5000)
