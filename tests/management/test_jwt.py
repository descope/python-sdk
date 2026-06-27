import pytest

from descope import AuthException
from descope.management.common import MgmtLoginOptions, MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestJWT:
    async def test_update_jwt(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response({}, status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.jwt.update_jwt("jwt", {"k1": "v1"}, 0))

            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.jwt.update_jwt("", {"k1": "v1"}, 0))

        # Test success flow
        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            resp = await client.invoke(client.mgmt.jwt.update_jwt("test", {"k1": "v1"}, 40))
            assert resp == "response"
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.update_jwt_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "jwt": "test",
                    "customClaims": {"k1": "v1"},
                    "refreshDuration": 40,
                },
                follow_redirects=False,
                params=None,
            )

        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            resp = await client.invoke(client.mgmt.jwt.update_jwt("test", {"k1": "v1"}))
            assert resp == "response"
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.update_jwt_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "jwt": "test",
                    "customClaims": {"k1": "v1"},
                    "refreshDuration": 0,
                },
                follow_redirects=False,
                params=None,
            )

    async def test_impersonate(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response({}, status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.jwt.impersonate("imp1", "imp2", False))

            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.jwt.impersonate("", "imp2", False))

            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.jwt.impersonate("imp1", "", False))

        # Test success flow
        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            resp = await client.invoke(client.mgmt.jwt.impersonate("imp1", "imp2", True))
            assert resp == "response"
            expected_uri = f"{DEFAULT_BASE_URL}{MgmtV1.impersonate_path}"
            assert_http_called(
                mock,
                client.mode,
                expected_uri,
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "imp2",
                    "impersonatorId": "imp1",
                    "validateConsent": True,
                    "customClaims": None,
                    "selectedTenant": None,
                    "refreshDuration": None,
                    "stepup": None,
                },
                follow_redirects=False,
                params=None,
            )

        # Test stepup flow
        with client.mock_mgmt_post(make_response({"jwt": "stepup_response"})) as mock:
            resp = await client.invoke(client.mgmt.jwt.impersonate("imp1", "imp2", True, stepup=True))
            assert resp == "stepup_response"
            assert_http_called(
                mock,
                client.mode,
                expected_uri,
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "imp2",
                    "impersonatorId": "imp1",
                    "validateConsent": True,
                    "customClaims": None,
                    "selectedTenant": None,
                    "refreshDuration": None,
                    "stepup": True,
                },
                follow_redirects=False,
                params=None,
            )

    async def test_stop_impersonation(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response({}, status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.jwt.stop_impersonation(""))

        # Test success flow
        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            resp = await client.invoke(client.mgmt.jwt.stop_impersonation("jwtstr"))
            assert resp == "response"
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.stop_impersonation_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "jwt": "jwtstr",
                    "customClaims": None,
                    "selectedTenant": None,
                    "refreshDuration": None,
                },
                follow_redirects=False,
                params=None,
            )

    async def test_sign_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with pytest.raises(AuthException):
            await client.invoke(client.mgmt.jwt.sign_in(""))

        with pytest.raises(AuthException):
            await client.invoke(client.mgmt.jwt.sign_in("loginId", MgmtLoginOptions(mfa=True)))

        # Test success flow
        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            await client.invoke(client.mgmt.jwt.sign_in("loginId"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_in_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "loginId",
                    "stepup": False,
                    "mfa": False,
                    "revokeOtherSessions": None,
                    "customClaims": None,
                    "jwt": None,
                    "refreshDuration": None,
                },
                follow_redirects=False,
                params=None,
            )

    async def test_sign_up(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with pytest.raises(AuthException):
            await client.invoke(client.mgmt.jwt.sign_up(""))

        # Test success flow
        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            await client.invoke(client.mgmt.jwt.sign_up("loginId"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_up_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "loginId",
                    "user": {
                        "name": None,
                        "givenName": None,
                        "middleName": None,
                        "familyName": None,
                        "phone": None,
                        "email": None,
                        "emailVerified": None,
                        "phoneVerified": None,
                        "ssoAppId": None,
                    },
                    "emailVerified": None,
                    "phoneVerified": None,
                    "ssoAppId": None,
                    "customClaims": None,
                    "refreshDuration": None,
                },
                follow_redirects=False,
                params=None,
            )

    async def test_sign_up_or_in(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with pytest.raises(AuthException):
            await client.invoke(client.mgmt.jwt.sign_up_or_in(""))

        # Test success flow
        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            await client.invoke(client.mgmt.jwt.sign_up_or_in("loginId"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_sign_up_or_in_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "loginId",
                    "user": {
                        "name": None,
                        "givenName": None,
                        "middleName": None,
                        "familyName": None,
                        "phone": None,
                        "email": None,
                        "emailVerified": None,
                        "phoneVerified": None,
                        "ssoAppId": None,
                    },
                    "emailVerified": None,
                    "phoneVerified": None,
                    "ssoAppId": None,
                    "customClaims": None,
                    "refreshDuration": None,
                },
                follow_redirects=False,
                params=None,
            )

    async def test_anonymous(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow
        with client.mock_mgmt_post(make_response({"jwt": "response"})) as mock:
            await client.invoke(client.mgmt.jwt.anonymous({"k1": "v1"}, "id"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.anonymous_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "customClaims": {"k1": "v1"},
                    "selectedTenant": "id",
                    "refreshDuration": None,
                },
                follow_redirects=False,
                params=None,
            )
