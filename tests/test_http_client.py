import importlib
import importlib.util
import sys
import types
import unittest
from unittest.mock import Mock, patch

from descope.http_client import DescopeResponse, HTTPClient


class TestDescopeResponse(unittest.TestCase):
    def test_dict_like_access(self):
        """Test that DescopeResponse acts like a dict for backward compatibility."""
        mock_response = Mock()
        mock_response.json.return_value = {"user": {"id": "u1"}, "status": "ok"}
        mock_response.headers = {"cf-ray": "abc123"}
        mock_response.status_code = 200

        resp = DescopeResponse(mock_response)

        # Dict-like access
        assert resp["user"]["id"] == "u1"
        assert resp["status"] == "ok"
        assert "user" in resp
        assert "missing" not in resp
        assert resp.get("status") == "ok"
        assert resp.get("missing", "default") == "default"
        assert list(resp.keys()) == ["user", "status"]
        assert len(resp) == 2

    def test_http_metadata_access(self):
        """Test that HTTP metadata is accessible."""
        mock_response = Mock()
        mock_response.json.return_value = {"result": "success"}
        mock_response.headers = {"cf-ray": "abc123", "x-request-id": "req456"}
        mock_response.status_code = 201
        mock_response.text = '{"result":"success"}'
        mock_response.url = "https://api.descope.com/test"
        mock_response.ok = True

        resp = DescopeResponse(mock_response)

        # HTTP metadata
        assert resp.headers.get("cf-ray") == "abc123"
        assert resp.headers.get("x-request-id") == "req456"
        assert resp.status_code == 201
        assert resp.text == '{"result":"success"}'
        assert resp.url == "https://api.descope.com/test"
        assert resp.ok is True

    def test_json_caching(self):
        """Test that JSON parsing is cached."""
        mock_response = Mock()
        mock_response.json.return_value = {"data": "value"}

        resp = DescopeResponse(mock_response)

        # First call
        result1 = resp.json()
        # Second call should use cached value
        result2 = resp.json()

        assert result1 == result2
        # json() should only be called once on the underlying response
        assert mock_response.json.call_count == 1

    def test_dict_like_values_items(self):
        """Test that values() and items() work correctly."""
        mock_response = Mock()
        mock_response.json.return_value = {"a": 1, "b": 2}
        resp = DescopeResponse(mock_response)

        assert list(resp.values()) == [1, 2]
        assert list(resp.items()) == [("a", 1), ("b", 2)]

    def test_string_representation(self):
        """Test __str__ and __repr__ methods."""
        mock_response = Mock()
        mock_response.json.return_value = {"result": "success"}
        resp = DescopeResponse(mock_response)

        assert str(resp) == "{'result': 'success'}"
        assert "DescopeResponse" in repr(resp)

    def test_bool_and_len(self):
        """Test __bool__ and __len__ methods."""
        mock_response = Mock()
        mock_response.json.return_value = {"data": "value"}
        resp = DescopeResponse(mock_response)

        assert bool(resp) is True
        assert len(resp) == 1

    def test_equality(self):
        """Test __eq__ and __ne__ methods."""
        mock1 = Mock()
        mock1.json.return_value = {"data": "value"}
        mock2 = Mock()
        mock2.json.return_value = {"data": "value"}
        mock3 = Mock()
        mock3.json.return_value = {"different": "data"}

        resp1 = DescopeResponse(mock1)
        resp2 = DescopeResponse(mock2)
        resp3 = DescopeResponse(mock3)

        assert resp1 == resp2
        assert resp1 != resp3
        assert resp1 == {"data": "value"}

    def test_iter(self):
        """Test __iter__ method."""
        mock_response = Mock()
        mock_response.json.return_value = {"a": 1, "b": 2}
        resp = DescopeResponse(mock_response)

        assert list(resp) == ["a", "b"]

    def test_cookies_and_content(self):
        """Test cookies and content properties."""
        mock_response = Mock()
        mock_response.json.return_value = {"data": "test"}
        mock_response.cookies = {"session": "abc123"}
        mock_response.content = b'{"data":"test"}'
        resp = DescopeResponse(mock_response)

        assert resp.cookies.get("session") == "abc123"
        assert resp.content == b'{"data":"test"}'

    @patch("requests.get")
    def test_verbose_mode_captures_response_before_error(self, mock_get):
        """Test that verbose mode captures response even when errors are raised.

        This is critical for debugging - the whole point of verbose mode is to
        capture headers (cf-ray) from failed requests to share with support.
        """
        from descope.exceptions import AuthException

        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.headers = {"cf-ray": "error123"}
        mock_response.json.return_value = {"error": "Unauthorized"}
        mock_get.return_value = mock_response

        client = HTTPClient(project_id="test123", verbose=True)
        try:
            client.get("/test")
            assert False, "Should have raised AuthException"
        except AuthException:
            pass

        last_resp = client.get_last_response()
        assert (
            last_resp is not None
        ), "Response should be captured even when error occurs"
        assert last_resp.status_code == 401
        assert last_resp.headers.get("cf-ray") == "error123"
        assert last_resp.text == "Unauthorized"


class TestHTTPClient(unittest.TestCase):
    def test_base_url_for_project_id(self):
        # short project id -> default base
        assert HTTPClient.base_url_for_project_id("short") == "https://api.descope.com"
        # long project id -> computed region
        pid = "Puse12aAc4T2V93bddihGEx2Ryhc8e5Z"
        assert HTTPClient.base_url_for_project_id(pid) == "https://api.use1.descope.com"

    def test_verbose_mode_disabled_by_default(self):
        """Test that verbose mode is disabled by default."""
        client = HTTPClient(project_id="test123")
        assert client.verbose is False
        assert client.get_last_response() is None

    def test_verbose_mode_enabled(self):
        """Test that verbose mode can be enabled."""
        client = HTTPClient(project_id="test123", verbose=True)
        assert client.verbose is True

    @patch("requests.get")
    def test_verbose_mode_captures_response(self, mock_get):
        """Test that responses are captured when verbose mode is enabled."""
        # Setup mock response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"data": "test"}
        mock_response.headers = {"cf-ray": "xyz789"}
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Create client with verbose mode
        client = HTTPClient(project_id="test123", verbose=True)

        # Make a request
        client.get("/test")

        # Verify response was captured
        last_resp = client.get_last_response()
        assert last_resp is not None
        assert last_resp["data"] == "test"
        assert last_resp.headers.get("cf-ray") == "xyz789"
        assert last_resp.status_code == 200

    @patch("requests.get")
    def test_verbose_mode_not_capture_when_disabled(self, mock_get):
        """Test that responses are NOT captured when verbose mode is disabled."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"data": "test"}
        mock_get.return_value = mock_response

        # Create client WITHOUT verbose mode
        client = HTTPClient(project_id="test123", verbose=False)

        # Make a request
        client.get("/test")

        # Verify response was NOT captured
        assert client.get_last_response() is None

    @patch("requests.post")
    def test_verbose_mode_captures_post_response(self, mock_post):
        """Test that POST responses are captured in verbose mode."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"created": "user1"}
        mock_response.headers = {"cf-ray": "post123"}
        mock_response.status_code = 201
        mock_post.return_value = mock_response

        client = HTTPClient(project_id="test123", verbose=True)
        client.post("/users", body={"name": "test"})

        last_resp = client.get_last_response()
        assert last_resp is not None
        assert last_resp["created"] == "user1"
        assert last_resp.status_code == 201

    @patch("requests.patch")
    def test_verbose_mode_captures_patch_response(self, mock_patch):
        """Test that PATCH responses are captured in verbose mode."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"updated": "user1"}
        mock_response.headers = {"cf-ray": "patch123"}
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        client = HTTPClient(project_id="test123", verbose=True)
        client.patch("/users/1", body={"name": "updated"})

        last_resp = client.get_last_response()
        assert last_resp is not None
        assert last_resp["updated"] == "user1"
        assert last_resp.status_code == 200

    @patch("requests.delete")
    def test_verbose_mode_captures_delete_response(self, mock_delete):
        """Test that DELETE responses are captured in verbose mode."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"deleted": "user1"}
        mock_response.headers = {"cf-ray": "delete123"}
        mock_response.status_code = 204
        mock_delete.return_value = mock_response

        client = HTTPClient(project_id="test123", verbose=True)
        client.delete("/users/1")

        last_resp = client.get_last_response()
        assert last_resp is not None
        assert last_resp["deleted"] == "user1"
        assert last_resp.status_code == 204

    def test_raises_auth_exception_with_empty_project_id(self):
        """Test that HTTPClient raises AuthException when project_id is empty."""
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException) as cm:
            HTTPClient(project_id="")

        assert cm.exception.status_code == 400

    @patch("requests.get")
    def test_raises_rate_limit_exception(self, mock_get):
        """Test that HTTPClient raises RateLimitException on 429."""
        from descope.exceptions import RateLimitException

        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 429
        mock_response.json.return_value = {
            "errorCode": "E010",
            "errorDescription": "Rate limit exceeded",
            "errorMessage": "Too many requests",
        }
        mock_response.headers = {"Retry-After": "60"}
        mock_get.return_value = mock_response

        client = HTTPClient(project_id="test123")

        with self.assertRaises(RateLimitException) as cm:
            client.get("/test")

        assert cm.exception.error_type == "API rate limit exceeded"

    @patch("requests.get")
    def test_raises_rate_limit_exception_without_json_body(self, mock_get):
        """Test that RateLimitException is raised even when JSON parsing fails."""
        from descope.exceptions import RateLimitException

        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 429
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.headers = {"Retry-After": "30"}
        mock_get.return_value = mock_response

        client = HTTPClient(project_id="test123")

        with self.assertRaises(RateLimitException) as cm:
            client.get("/test")

        assert cm.exception.error_type == "API rate limit exceeded"

    @patch("requests.get")
    def test_raises_auth_exception_on_server_error(self, mock_get):
        """Test that HTTPClient raises AuthException on 500."""
        from descope.exceptions import AuthException

        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        client = HTTPClient(project_id="test123")

        with self.assertRaises(AuthException) as cm:
            client.get("/test")

        assert cm.exception.status_code == 500

    def test_get_default_headers_with_password(self):
        """Test get_default_headers with password."""
        client = HTTPClient(project_id="test123")
        headers = client.get_default_headers("mypassword")
        assert "Authorization" in headers
        assert "test123:mypassword" in headers["Authorization"]

    def test_get_default_headers_with_management_key(self):
        """Test get_default_headers with management key."""
        client = HTTPClient(project_id="test123", management_key="mgmt-key")
        headers = client.get_default_headers()
        assert "Authorization" in headers
        assert "test123:mgmt-key" in headers["Authorization"]

    def test_parse_retry_after_with_valid_header(self):
        """Test _parse_retry_after with valid header."""
        client = HTTPClient(project_id="test123")
        headers = {"Retry-After": "60"}
        result = client._parse_retry_after(headers)
        assert result == 60

    def test_parse_retry_after_with_missing_header(self):
        """Test _parse_retry_after with missing header."""
        client = HTTPClient(project_id="test123")
        headers = {}
        result = client._parse_retry_after(headers)
        assert result == 0

    def test_parse_retry_after_with_invalid_header(self):
        """Test _parse_retry_after with invalid header."""
        client = HTTPClient(project_id="test123")
        headers = {"Retry-After": "not-a-number"}
        result = client._parse_retry_after(headers)
        assert result == 0

    @unittest.skipIf(
        importlib.util.find_spec("importlib.metadata") is not None,
        "Stdlib metadata available; skip fallback path test",
    )
    def test_sdk_version_import_fallback(self):
        # Simulate absence of importlib.metadata to take fallback path
        import builtins

        import descope.http_client as http_client_mod

        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "importlib.metadata":
                raise ImportError("simulated")
            return original_import(name, globals, locals, fromlist, level)

        # Prepare a fake pkg_resources for fallback path
        class FakeDist:
            def __init__(self, version="0.0.0"):
                self.version = version

        fake_pkg = types.ModuleType("pkg_resources")
        fake_pkg.get_distribution = lambda name: FakeDist("9.9.9")  # type: ignore

        saved_pkg = sys.modules.get("pkg_resources")
        sys.modules["pkg_resources"] = fake_pkg

        try:
            builtins.__import__ = fake_import
            reloaded = importlib.reload(http_client_mod)
            v = reloaded.sdk_version()
            assert isinstance(v, str)
        finally:
            builtins.__import__ = original_import
            if saved_pkg is not None:
                sys.modules["pkg_resources"] = saved_pkg
            else:
                sys.modules.pop("pkg_resources", None)


if __name__ == "__main__":
    unittest.main()
