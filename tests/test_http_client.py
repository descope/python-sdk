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
