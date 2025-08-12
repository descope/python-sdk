from __future__ import annotations

import datetime
import uuid
from functools import wraps

from flask import Response, g, redirect, request

from .. import (
    COOKIE_DATA_NAME,
    REFRESH_SESSION_COOKIE_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_COOKIE_NAME,
    SESSION_TOKEN_NAME,
    AuthException,
    DeliveryMethod,
)
from ..descope_client import DescopeClient
from ..exceptions import ERROR_TYPE_INVALID_ARGUMENT


def set_cookie_on_response(response: Response, token: dict, cookie_data: dict):
    cookie_domain = cookie_data.get("domain", "")
    if cookie_domain == "":
        cookie_domain = None

    current_time = datetime.datetime.now()
    expire_time = current_time + datetime.timedelta(days=30)

    return response.set_cookie(
        key=token.get("drn", ""),
        value=token.get("jwt", ""),
        max_age=cookie_data.get("maxAge", int(expire_time.timestamp())),
        expires=cookie_data.get("exp", expire_time),
        path=cookie_data.get("path", "/"),
        domain=cookie_domain,
        secure=False,  # True
        httponly=True,
        samesite="Strict",  # "Strict", "Lax", "None"
    )


def descope_signup_otp_by_email(descope_client: DescopeClient):
    """
    Sign-up new user, using email to verify the OTP
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            user = data.get("user", None)
            if not email or email == "":
                return Response("Invalid Request, missing email", 400)

            try:
                descope_client.otp.sign_up(DeliveryMethod.EMAIL, email, user)
            except AuthException as e:
                return Response(f"Unable to sign-up user, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_signin_otp_by_email(descope_client: DescopeClient):
    """
    Sign-in existing user, using email to verify OTP
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            if not email:
                return Response("Invalid Request, missing email", 400)

            try:
                descope_client.otp.sign_in(DeliveryMethod.EMAIL, email)
            except AuthException as e:
                return Response(f"Unable to sign-in, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_validate_auth(
    descope_client: DescopeClient,
    permissions: list[str] | None = None,
    roles: list[str] | None = None,
    tenant="",
):
    """
    Test if Access Token is valid
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            _permissions = [] if permissions is None else permissions
            _roles = [] if roles is None else roles

            cookies = request.cookies.copy()
            session_token = cookies.get(SESSION_COOKIE_NAME, None)
            refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
            try:
                jwt_response = descope_client.validate_and_refresh_session(
                    session_token, refresh_token
                )

            except AuthException:
                return Response("Access denied", 401)

            if _permissions:
                if tenant:
                    valid_permissions = descope_client.validate_tenant_permissions(
                        jwt_response, _permissions
                    )
                else:
                    valid_permissions = descope_client.validate_permissions(
                        jwt_response, _permissions
                    )

                if not valid_permissions:
                    return Response("Access denied", 401)

            if _roles:
                if tenant:
                    valid_roles = descope_client.validate_tenant_roles(
                        jwt_response, _roles
                    )
                else:
                    valid_roles = descope_client.validate_roles(jwt_response, _roles)

                if not valid_roles:
                    return Response("Access denied", 401)

            # Save the claims on the context execute the original API
            g.claims = jwt_response
            response = f(*args, **kwargs)

            if jwt_response.get(COOKIE_DATA_NAME, None):
                set_cookie_on_response(
                    response,
                    jwt_response[SESSION_TOKEN_NAME],
                    jwt_response[COOKIE_DATA_NAME],
                )
            return response

        return decorated

    return decorator


def descope_verify_code_by_email(descope_client: DescopeClient):
    """
    Verify code by email decorator
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            code = data.get("code", None)
            if not code or not email:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.EMAIL, email, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            g.claims = jwt_response
            response = f(*args, **kwargs)

            set_cookie_on_response(
                response,
                jwt_response[SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )
            set_cookie_on_response(
                response,
                jwt_response[REFRESH_SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )
            return response

        return decorated

    return decorator


def descope_verify_code_by_phone_sms(descope_client: DescopeClient):
    """
    Verify code by phone sms decorator
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            phone = data.get("phone", None)
            code = data.get("code", None)
            if not code or not phone:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.SMS, phone, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            g.claims = jwt_response
            response = f(*args, **kwargs)

            set_cookie_on_response(
                response,
                jwt_response[SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )
            set_cookie_on_response(
                response,
                jwt_response[REFRESH_SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )

            return response

        return decorated

    return decorator


def descope_verify_code_by_phone_voice_call(descope_client: DescopeClient):
    """
    Verify code by phone voice call decorator
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            phone = data.get("phone", None)
            code = data.get("code", None)
            if not code or not phone:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.VOICE, phone, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            g.claims = jwt_response
            response = f(*args, **kwargs)

            set_cookie_on_response(
                response,
                jwt_response[SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )
            set_cookie_on_response(
                response,
                jwt_response[REFRESH_SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )

            return response

        return decorated

    return decorator


def descope_verify_code_by_phone_whatsapp(descope_client: DescopeClient):
    """
    Verify code by phone whatsapp decorator
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            phone = data.get("phone", None)
            code = data.get("code", None)
            if not code or not phone:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.WHATSAPP, phone, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            g.claims = jwt_response
            response = f(*args, **kwargs)

            set_cookie_on_response(
                response,
                jwt_response[SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )
            set_cookie_on_response(
                response,
                jwt_response[REFRESH_SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )

            return response

        return decorated

    return decorator


def descope_signup_magiclink_by_email(descope_client: DescopeClient, uri: str):
    """
    Signup new user using magiclink via email
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            user = data.get("user", None)
            if not email or email == "":
                return Response("Bad Request, missing email", 400)

            try:
                descope_client.magiclink.sign_up(DeliveryMethod.EMAIL, email, uri, user)
            except AuthException as e:
                return Response(f"Failed to signup, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_signin_magiclink_by_email(descope_client: DescopeClient, uri: str):
    """
    Signin using magiclink via email
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            if not email:
                return Response("Bad Request, missing email", 400)

            try:
                descope_client.magiclink.sign_in(DeliveryMethod.EMAIL, email, uri)
            except AuthException as e:
                return Response(f"Failed to signin, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_verify_magiclink_token(descope_client: DescopeClient):
    """
    Verify magiclink token
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            code = request.args.get("t")
            if not code:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.magiclink.verify(code)
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            g.claims = jwt_response
            response = f(*args, **kwargs)

            set_cookie_on_response(
                response,
                jwt_response[SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )
            set_cookie_on_response(
                response,
                jwt_response[REFRESH_SESSION_TOKEN_NAME],
                jwt_response[COOKIE_DATA_NAME],
            )
            return response

        return decorated

    return decorator


def descope_logout(descope_client: DescopeClient):
    """
    Logout
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cookies = request.cookies.copy()
            refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME)
            cookie_domain = request.headers.get("Host", "")
            try:
                descope_client.logout(refresh_token)
            except AuthException as e:
                return Response(f"Logout failed {e}", e.status_code)

            # Execute the original API
            response = f(*args, **kwargs)

            # Invalidate all cookies
            if cookie_domain:
                response.delete_cookie(SESSION_COOKIE_NAME, "/", cookie_domain)
                response.delete_cookie(REFRESH_SESSION_COOKIE_NAME, "/", cookie_domain)
            return response

        return decorated

    return decorator


def descope_oauth(descope_client: DescopeClient):
    """
    OAuth login
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                args = request.args
                provider = args.get("provider")
                redirect_url = descope_client.oauth.start(provider)
            except AuthException as e:
                return Response(f"OAuth failed {e}", e.status_code)

            # Execute the original API
            # (ignore return value as anyway we redirect)
            f(*args, **kwargs)

            return redirect(redirect_url["url"], 302)

        return decorated

    return decorator


def descope_full_login(project_id: str, flow_id: str, success_redirect_url: str):
    """
    Descope Flow login
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            id = f"descope-{uuid.uuid4()}"
            if not success_redirect_url:
                raise AuthException(
                    500,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    "Missing success_redirect_url parameter",
                )

            html = f"""<!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <script src="https://unpkg.com/@descope/web-component/dist/index.js"></script>
                        </head>

                        <body>
                            <descope-wc id="{id}" project-id="{project_id}" flow-id="{flow_id}"></descope-wc>
                            <script>
                                const setCookie = (cookieName, cookieValue, maxAge, path, domain) => {{
                                    document.cookie = cookieName + '=' + cookieValue + ';max-age=' + maxAge + ';path=' + path + ';domain=' + domain + '; samesite=strict; secure;'
                                }}
                                const descopeWcEle = document.getElementById('{id}');
                                descopeWcEle.addEventListener('success', async (e) => {{
                                    setCookie('{SESSION_COOKIE_NAME}', e.detail.sessionJwt, e.detail.cookieMaxAge, e.detail.cookiePath, e.detail.cookieDomain)
                                    setCookie('{REFRESH_SESSION_COOKIE_NAME}', e.detail.refreshJwt, e.detail.cookieMaxAge, e.detail.cookiePath, e.detail.cookieDomain)

                                    document.location.replace("{success_redirect_url}")
                                }});
                            </script>
                        </body>
                        </html>"""
            f(*args, **kwargs)
            return html

        return decorated

    return decorator
