import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest

from descope import AuthException
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT

from . import common


class TestApp:
    def test_validate_return_url(self):
        from descope.authmethod.app import App

        App._validate_return_url("https://x.com/cb")
        with pytest.raises(AuthException):
            App._validate_return_url(None)
        with pytest.raises(AuthException):
            App._validate_return_url("")

    def test_generate_pkce_pair(self):
        from descope.authmethod.app import App

        verifier, challenge = App._generate_pkce_pair()
        assert 43 <= len(verifier) <= 128
        expected_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .decode("ascii")
            .rstrip("=")
        )
        assert challenge == expected_challenge
        assert "=" not in challenge

        # each call generates a fresh, unique pair
        verifier2, _ = App._generate_pkce_pair()
        assert verifier != verifier2

    def test_build_oidc_client_id_matches_live_console_value(self):
        """Regression lock: reproduces a real console-issued clientId byte-for-byte
        (verified live against project P3I9XNBUps4jHk4ybbaezDSu7mjH's "Generic OIDC
        Application", app SA3I9XPZkJYkcCwN34D77fNpGL1D9)."""
        from descope.authmethod.app import App

        assert App._build_oidc_client_id(
            "P3I9XNBUps4jHk4ybbaezDSu7mjH", "SA3I9XPZkJYkcCwN34D77fNpGL1D9"
        ) == "UDNJOVhOQlVwczRqSGs0eWJiYWV6RFN1N21qSDpTQTNJOVhQWmtKWWtjQ3dOMzRENzdmTnBHTDFEOSMj"

    def test_build_oidc_client_id_padding(self):
        from descope.authmethod.app import App

        for project_id, app_id in [("P1", "app1"), ("P12", "app1"), ("P123", "app1")]:
            raw = f"{project_id}:{app_id}"
            client_id = App._build_oidc_client_id(project_id, app_id)
            assert "=" not in client_id
            decoded = base64.b64decode(client_id).decode("ascii")
            assert decoded.rstrip("#") == raw

    def test_compose_oidc_authorize_url(self):
        from descope.authmethod.app import App

        url = App._compose_oidc_authorize_url(
            "http://x.com",
            "P1",
            "app1",
            "https://cb.com",
            "tenant1",
            "user@d.com",
            "openid",
            "state1",
            "chal1",
            "custom-mfa-flow",
        )
        assert url.startswith("http://x.com/oauth2/v1/P1/authorize?")
        query = parse_qs(urlsplit(url).query)
        assert query == {
            "response_type": ["code"],
            "client_id": [App._build_oidc_client_id("P1", "app1")],
            "redirect_uri": ["https://cb.com"],
            "scope": ["openid"],
            "state": ["state1"],
            "code_challenge": ["chal1"],
            "code_challenge_method": ["S256"],
            "tenant": ["tenant1"],
            "login_hint": ["user@d.com"],
            "flow": ["custom-mfa-flow"],
        }

        # flow is opt-in - omitted entirely when not given
        url_no_flow = App._compose_oidc_authorize_url(
            "http://x.com", "P1", "app1", "https://cb.com", "", "", "openid", "state1", "chal1", ""
        )
        assert "flow" not in parse_qs(urlsplit(url_no_flow).query)

    def test_compose_oidc_token_body(self):
        from descope.authmethod.app import App

        client_id = App._build_oidc_client_id("P1", "app1")
        assert App._compose_oidc_token_body("P1", "app1", "code1", "", "", "") == {
            "grant_type": "authorization_code",
            "code": "code1",
            "client_id": client_id,
        }
        assert App._compose_oidc_token_body(
            "P1", "app1", "code1", "verifier1", "secret1", "https://cb.com"
        ) == {
            "grant_type": "authorization_code",
            "code": "code1",
            "client_id": client_id,
            "code_verifier": "verifier1",
            "client_secret": "secret1",
            "redirect_uri": "https://cb.com",
        }

    async def test_start(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors - app_id
        with pytest.raises(AuthException):
            await client.invoke(client.app.start("", "https://cb.com"))
        with pytest.raises(AuthException):
            await client.invoke(client.app.start(None, "https://cb.com"))

        # Validation errors - return_url is required
        with pytest.raises(AuthException):
            await client.invoke(client.app.start("app1", None))
        with pytest.raises(AuthException):
            await client.invoke(client.app.start("app1", ""))

        # No network call is made - start() builds the URL and PKCE pair locally
        result = await client.invoke(client.app.start("app1", "https://cb.com"))
        assert set(result.keys()) == {"url", "state", "code_verifier"}
        assert result["url"].startswith(f"{common.DEFAULT_BASE_URL}/oauth2/v1/{PROJECT_ID}/authorize?")
        query = parse_qs(urlsplit(result["url"]).query)
        assert query["response_type"] == ["code"]
        from descope.authmethod.app import App

        assert query["client_id"] == [App._build_oidc_client_id(PROJECT_ID, "app1")]
        assert query["redirect_uri"] == ["https://cb.com"]
        assert query["scope"] == ["openid"]
        assert query["state"] == [result["state"]]
        assert query["code_challenge_method"] == ["S256"]
        assert "code_challenge" in query

        # caller-supplied state is honored instead of a generated one
        result = await client.invoke(client.app.start("app1", "https://cb.com", state="my-state"))
        assert result["state"] == "my-state"
        assert parse_qs(urlsplit(result["url"]).query)["state"] == ["my-state"]

        # homegrown-first-factor + Descope-for-MFA-only pattern: flow + login_hint together
        result = await client.invoke(
            client.app.start(
                "app1",
                "https://cb.com",
                login_hint="user@d.com",
                flow="custom-mfa-flow",
            )
        )
        query = parse_qs(urlsplit(result["url"]).query)
        assert query["flow"] == ["custom-mfa-flow"]
        assert query["login_hint"] == ["user@d.com"]

    async def test_exchange_token(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT)

        # Validation errors
        with pytest.raises(AuthException):
            await client.invoke(client.app.exchange_token("", "code1"))
        with pytest.raises(AuthException):
            await client.invoke(client.app.exchange_token("app1", ""))
        with pytest.raises(AuthException):
            await client.invoke(client.app.exchange_token("app1", None))

        # HTTP error
        with client.mock_post(make_response(status=400)):
            with pytest.raises(AuthException):
                await client.invoke(client.app.exchange_token("app1", "code1"))

        # Success - note the raw OAuth2/OIDC response shape, not sessionJwt/refreshJwt
        oidc_tokens = {
            "access_token": "at1",
            "token_type": "Bearer",
            "refresh_token": "rt1",
            "id_token": "idt1",
            "expires_in": 3600,
            "scope": "openid",
        }
        with client.mock_post(make_response(oidc_tokens)) as mock_post:
            result = await client.invoke(
                client.app.exchange_token(
                    "app1", "code1", code_verifier="verifier1", redirect_uri="https://cb.com"
                )
            )
        assert result == oidc_tokens
        from descope.authmethod.app import App

        assert_http_called(
            mock_post,
            client.mode,
            f"{common.DEFAULT_BASE_URL}/oauth2/v1/{PROJECT_ID}/token",
            data={
                "grant_type": "authorization_code",
                "code": "code1",
                "client_id": App._build_oidc_client_id(PROJECT_ID, "app1"),
                "code_verifier": "verifier1",
                "redirect_uri": "https://cb.com",
            },
            follow_redirects=False,
        )
