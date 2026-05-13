import os
import unittest
from unittest.mock import Mock, patch

from descope.exceptions import AuthException
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
        mock_response.is_success = True

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

    @patch("httpx.get")
    def test_verbose_mode_captures_response_before_error(self, mock_get):
        """Test that verbose mode captures response even when errors are raised.

        This is critical for debugging - the whole point of verbose mode is to
        capture headers (cf-ray) from failed requests to share with support.
        """
        from descope.exceptions import AuthException

        mock_response = Mock()
        mock_response.is_success = False
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.headers = {"cf-ray": "error123"}
        mock_response.json.return_value = {"error": "Unauthorized"}
        mock_get.return_value = mock_response

        client = HTTPClient(project_id="test123", verbose=True)
        try:
            client.get("/test")
            raise AssertionError("Should have raised AuthException")
        except AuthException:
            pass

        last_resp = client.get_last_response()
        assert last_resp is not None, "Response should be captured even when error occurs"
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

    @patch("httpx.get")
    def test_verbose_mode_captures_response(self, mock_get):
        """Test that responses are captured when verbose mode is enabled."""
        # Setup mock response
        mock_response = Mock()
        mock_response.is_success = True
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

    @patch("httpx.get")
    def test_verbose_mode_not_capture_when_disabled(self, mock_get):
        """Test that responses are NOT captured when verbose mode is disabled."""
        mock_response = Mock()
        mock_response.is_success = True
        mock_response.json.return_value = {"data": "test"}
        mock_get.return_value = mock_response

        # Create client WITHOUT verbose mode
        client = HTTPClient(project_id="test123", verbose=False)

        # Make a request
        client.get("/test")

        # Verify response was NOT captured
        assert client.get_last_response() is None

    @patch("httpx.post")
    def test_verbose_mode_captures_post_response(self, mock_post):
        """Test that POST responses are captured in verbose mode."""
        mock_response = Mock()
        mock_response.is_success = True
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

    @patch("httpx.patch")
    def test_verbose_mode_captures_patch_response(self, mock_patch):
        """Test that PATCH responses are captured in verbose mode."""
        mock_response = Mock()
        mock_response.is_success = True
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

    @patch("httpx.delete")
    def test_verbose_mode_captures_delete_response(self, mock_delete):
        """Test that DELETE responses are captured in verbose mode."""
        mock_response = Mock()
        mock_response.is_success = True
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

    @patch("httpx.get")
    def test_raises_rate_limit_exception(self, mock_get):
        """Test that HTTPClient raises RateLimitException on 429."""
        from descope.exceptions import RateLimitException

        mock_response = Mock()
        mock_response.is_success = False
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

    @patch("httpx.get")
    def test_raises_rate_limit_exception_without_json_body(self, mock_get):
        """Test that RateLimitException is raised even when JSON parsing fails."""
        from descope.exceptions import RateLimitException

        mock_response = Mock()
        mock_response.is_success = False
        mock_response.status_code = 429
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.headers = {"Retry-After": "30"}
        mock_get.return_value = mock_response

        client = HTTPClient(project_id="test123")

        with self.assertRaises(RateLimitException) as cm:
            client.get("/test")

        assert cm.exception.error_type == "API rate limit exceeded"

    @patch("httpx.get")
    def test_raises_auth_exception_on_server_error(self, mock_get):
        """Test that HTTPClient raises AuthException on 500."""
        from descope.exceptions import AuthException

        mock_response = Mock()
        mock_response.is_success = False
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


class TestVerboseModeThreadSafety(unittest.TestCase):
    """Tests demonstrating verbose mode thread safety.

    The HTTPClient uses threading.local() to store _last_response, ensuring
    each thread gets its own response when sharing a client instance.
    """

    @patch("httpx.get")
    def test_verbose_mode_thread_safe_with_shared_client(self, mock_get):
        """Verify that shared client is thread-safe for verbose mode.

        Each thread should see its own response even when sharing the same
        HTTPClient instance, thanks to threading.local() storage.
        """
        import threading

        results: dict[str, str | None] = {
            "thread1_ray": None,
            "thread2_ray": None,
        }
        barrier = threading.Barrier(2)

        def mock_get_side_effect(*args, **kwargs):
            """Return different cf-ray based on which thread is calling."""
            thread_name = threading.current_thread().name
            response = Mock()
            response.is_success = True
            response.json.return_value = {"thread": thread_name}
            # Each thread gets a unique cf-ray
            if "thread1" in thread_name:
                response.headers = {"cf-ray": "ray-thread1"}
            else:
                response.headers = {"cf-ray": "ray-thread2"}
            response.status_code = 200
            return response

        mock_get.side_effect = mock_get_side_effect

        # Single shared client - now thread-safe!
        client = HTTPClient(project_id="test123", verbose=True)

        def thread1_work():
            client.get("/test")
            barrier.wait()  # Sync with thread2
            resp = client.get_last_response()
            assert resp is not None
            results["thread1_ray"] = resp.headers.get("cf-ray")

        def thread2_work():
            client.get("/test")
            barrier.wait()  # Sync with thread1
            resp = client.get_last_response()
            assert resp is not None
            results["thread2_ray"] = resp.headers.get("cf-ray")

        t1 = threading.Thread(target=thread1_work, name="thread1")
        t2 = threading.Thread(target=thread2_work, name="thread2")

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # With thread-local storage, each thread sees its OWN response
        assert results["thread1_ray"] == "ray-thread1", (
            f"Thread1 should see its own cf-ray, got: {results['thread1_ray']}"
        )
        assert results["thread2_ray"] == "ray-thread2", (
            f"Thread2 should see its own cf-ray, got: {results['thread2_ray']}"
        )

    @patch("httpx.get")
    def test_verbose_mode_separate_clients_per_thread(self, mock_get):
        """Verify separate clients per thread also works (alternative pattern).

        This test shows that using separate client instances per thread
        also provides thread-safe access to response metadata.
        """
        import threading

        results: dict[str, str | None] = {"thread1_ray": None, "thread2_ray": None}
        barrier = threading.Barrier(2)

        def mock_get_side_effect(*args, **kwargs):
            thread_name = threading.current_thread().name
            response = Mock()
            response.is_success = True
            response.json.return_value = {"thread": thread_name}
            if "thread1" in thread_name:
                response.headers = {"cf-ray": "ray-thread1"}
            else:
                response.headers = {"cf-ray": "ray-thread2"}
            response.status_code = 200
            return response

        mock_get.side_effect = mock_get_side_effect

        def thread1_work():
            # Each thread creates its own client
            client = HTTPClient(project_id="test123", verbose=True)
            client.get("/test")
            barrier.wait()
            resp = client.get_last_response()
            assert resp is not None
            results["thread1_ray"] = resp.headers.get("cf-ray")

        def thread2_work():
            # Each thread creates its own client
            client = HTTPClient(project_id="test123", verbose=True)
            client.get("/test")
            barrier.wait()
            resp = client.get_last_response()
            assert resp is not None
            results["thread2_ray"] = resp.headers.get("cf-ray")

        t1 = threading.Thread(target=thread1_work, name="thread1")
        t2 = threading.Thread(target=thread2_work, name="thread2")

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # With separate clients, each thread has its own response
        assert results["thread1_ray"] == "ray-thread1", (
            f"Thread1 should see its own cf-ray, got: {results['thread1_ray']}"
        )
        assert results["thread2_ray"] == "ray-thread2", (
            f"Thread2 should see its own cf-ray, got: {results['thread2_ray']}"
        )


class TestRetryMechanism(unittest.TestCase):
    """Tests for automatic retry on specific HTTP status codes."""

    @patch("time.sleep")
    @patch("httpx.get")
    def test_retries_on_retryable_codes(self, mock_get, mock_sleep):
        """Test that all retryable status codes (503, 521, 522, 524, 530) trigger a retry."""
        for status_code in [503, 521, 522, 524, 530]:
            mock_get.reset_mock()
            mock_sleep.reset_mock()

            error_response = Mock()
            error_response.is_success = False
            error_response.status_code = status_code
            error_response.text = f"Error {status_code}"

            success_response = Mock()
            success_response.is_success = True
            success_response.status_code = 200
            success_response.json.return_value = {"result": "ok"}

            mock_get.side_effect = [error_response, success_response]

            client = HTTPClient(project_id="test123")
            response = client.get("/test")

            assert mock_get.call_count == 2, f"Should retry once on {status_code}"
            assert response.status_code == 200
            mock_sleep.assert_called_once_with(0.1)

    @patch("time.sleep")
    @patch("httpx.get")
    def test_retries_up_to_three_times(self, mock_get, mock_sleep):
        """Test that the client retries up to 3 times (original + 3 retries = 4 calls)."""
        error_response = Mock()
        error_response.is_success = False
        error_response.status_code = 503
        error_response.text = "Service Unavailable"

        mock_get.return_value = error_response

        client = HTTPClient(project_id="test123")
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException):
            client.get("/test")

        # Original call + 3 retries = 4 total calls
        assert mock_get.call_count == 4
        assert mock_sleep.call_count == 3

    @patch("time.sleep")
    @patch("httpx.get")
    def test_retry_delays_are_correct(self, mock_get, mock_sleep):
        """Test that retry delays are: 100ms first, 5s for subsequent retries."""
        error_response = Mock()
        error_response.is_success = False
        error_response.status_code = 503
        error_response.text = "Service Unavailable"

        mock_get.return_value = error_response

        client = HTTPClient(project_id="test123")
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException):
            client.get("/test")

        sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
        assert sleep_calls == [0.1, 5.0, 5.0]

    @patch("time.sleep")
    @patch("httpx.get")
    def test_no_retry_on_non_retryable_codes(self, mock_get, mock_sleep):
        """Test that non-retryable status codes do not trigger retries."""
        for status_code in [400, 401, 403, 404, 500, 502]:
            mock_get.reset_mock()
            mock_sleep.reset_mock()

            error_response = Mock()
            error_response.is_success = False
            error_response.status_code = status_code
            error_response.text = f"Error {status_code}"
            mock_get.return_value = error_response

            client = HTTPClient(project_id="test123")
            from descope.exceptions import AuthException

            with self.assertRaises(AuthException):
                client.get("/test")

            assert mock_get.call_count == 1, f"Should not retry on {status_code}"
            mock_sleep.assert_not_called()

    @patch("time.sleep")
    @patch("httpx.post")
    def test_retry_works_for_post(self, mock_post, mock_sleep):
        """Test that retry works for POST requests."""
        error_response = Mock()
        error_response.is_success = False
        error_response.status_code = 503
        error_response.text = "Service Unavailable"

        success_response = Mock()
        success_response.is_success = True
        success_response.status_code = 200
        success_response.json.return_value = {"created": "ok"}

        mock_post.side_effect = [error_response, success_response]

        client = HTTPClient(project_id="test123")
        response = client.post("/test", body={"key": "value"})

        assert mock_post.call_count == 2
        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.1)

    @patch("time.sleep")
    @patch("httpx.put")
    def test_retry_works_for_put(self, mock_put, mock_sleep):
        """Test that retry works for PUT requests."""
        error_response = Mock()
        error_response.is_success = False
        error_response.status_code = 522
        error_response.text = "Connection Timed Out"

        success_response = Mock()
        success_response.is_success = True
        success_response.status_code = 200
        success_response.json.return_value = {"updated": "ok"}

        mock_put.side_effect = [error_response, success_response]

        client = HTTPClient(project_id="test123")
        response = client.put("/test", body={"key": "value"})

        assert mock_put.call_count == 2
        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.1)

    @patch("time.sleep")
    @patch("httpx.patch")
    def test_retry_works_for_patch(self, mock_patch, mock_sleep):
        """Test that retry works for PATCH requests."""
        error_response = Mock()
        error_response.is_success = False
        error_response.status_code = 530
        error_response.text = "Cloudflare Error"

        success_response = Mock()
        success_response.is_success = True
        success_response.status_code = 200
        success_response.json.return_value = {"patched": "ok"}

        mock_patch.side_effect = [error_response, success_response]

        client = HTTPClient(project_id="test123")
        response = client.patch("/test", body={"key": "value"})

        assert mock_patch.call_count == 2
        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.1)

    @patch("time.sleep")
    @patch("httpx.delete")
    def test_retry_works_for_delete(self, mock_delete, mock_sleep):
        """Test that retry works for DELETE requests."""
        error_response = Mock()
        error_response.is_success = False
        error_response.status_code = 503
        error_response.text = "Service Unavailable"

        success_response = Mock()
        success_response.is_success = True
        success_response.status_code = 200
        success_response.json.return_value = {"deleted": "ok"}

        mock_delete.side_effect = [error_response, success_response]

        client = HTTPClient(project_id="test123")
        response = client.delete("/test")

        assert mock_delete.call_count == 2
        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.1)

    @patch("time.sleep")
    @patch("httpx.get")
    def test_retry_succeeds_on_third_attempt(self, mock_get, mock_sleep):
        """Test successful response on 3rd retry (4th total call)."""
        error_response = Mock()
        error_response.is_success = False
        error_response.status_code = 503
        error_response.text = "Service Unavailable"

        success_response = Mock()
        success_response.is_success = True
        success_response.status_code = 200
        success_response.json.return_value = {"result": "ok"}

        mock_get.side_effect = [
            error_response,
            error_response,
            error_response,
            success_response,
        ]

        client = HTTPClient(project_id="test123")
        response = client.get("/test")

        assert mock_get.call_count == 4
        assert response.status_code == 200
        assert mock_sleep.call_count == 3
        sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
        assert sleep_calls == [0.1, 5.0, 5.0]

    @patch("time.sleep")
    @patch("httpx.get")
    def test_prior_response_closed_before_retry(self, mock_get, mock_sleep):
        """Test that each retried response is closed to release the connection pool slot."""
        error_response1 = Mock()
        error_response1.is_success = False
        error_response1.status_code = 503
        error_response1.text = "Service Unavailable"

        error_response2 = Mock()
        error_response2.is_success = False
        error_response2.status_code = 503
        error_response2.text = "Service Unavailable"

        success_response = Mock()
        success_response.is_success = True
        success_response.status_code = 200
        success_response.json.return_value = {"result": "ok"}

        mock_get.side_effect = [error_response1, error_response2, success_response]

        client = HTTPClient(project_id="test123")
        client.get("/test")

        # Each failed response must be closed before the next attempt
        error_response1.close.assert_called_once()
        error_response2.close.assert_called_once()
        # The final successful response is not closed here
        success_response.close.assert_not_called()

    @patch("time.sleep")
    @patch("httpx.get")
    def test_success_on_first_attempt_no_retry(self, mock_get, mock_sleep):
        """Test that no retry happens when the first attempt succeeds."""
        success_response = Mock()
        success_response.is_success = True
        success_response.status_code = 200
        success_response.json.return_value = {"result": "ok"}

        mock_get.return_value = success_response

        client = HTTPClient(project_id="test123")
        client.get("/test")

        assert mock_get.call_count == 1
        mock_sleep.assert_not_called()


class TestSSLConfiguration(unittest.TestCase):
    """Tests for SSL/TLS verification setup in HTTPClient."""

    # ------------------------------------------------------------------ #
    # client_verify attribute                                              #
    # ------------------------------------------------------------------ #

    def test_secure_default_uses_ssl_context(self):
        """secure=True (default) → client_verify is an SSLContext."""
        import ssl

        client = HTTPClient(project_id="test123")
        assert isinstance(client.client_verify, ssl.SSLContext)

    def test_secure_false_uses_plain_false(self):
        """secure=False → client_verify is the boolean False."""
        client = HTTPClient(project_id="test123", secure=False)
        assert client.client_verify is False

    def test_default_cert_source_is_certifi(self):
        """When no SSL env vars are set, certifi.where() is used as cafile."""
        import certifi

        with patch.dict(
            "os.environ",
            {},
            clear=False,
        ):
            # Remove all SSL overrides if present so we hit the default path
            for key in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"):
                os.environ.pop(key, None)

            with patch("descope.http_client.ssl.create_default_context") as mock_ctx_factory:
                mock_ssl_ctx = Mock()
                mock_ctx_factory.return_value = mock_ssl_ctx

                HTTPClient(project_id="test123", secure=True)

                mock_ctx_factory.assert_called_once_with(
                    cafile=certifi.where(),
                    capath=None,
                )

    def test_ssl_cert_file_env_overrides_certifi(self):
        """SSL_CERT_FILE replaces certifi.where() as the cafile."""
        with patch.dict("os.environ", {"SSL_CERT_FILE": "/tmp/custom.pem"}, clear=False):
            os.environ.pop("SSL_CERT_DIR", None)
            os.environ.pop("REQUESTS_CA_BUNDLE", None)

            with patch("descope.http_client.ssl.create_default_context") as mock_ctx_factory:
                mock_ctx_factory.return_value = Mock()

                HTTPClient(project_id="test123", secure=True)

                mock_ctx_factory.assert_called_once_with(
                    cafile="/tmp/custom.pem",
                    capath=None,
                )

    def test_ssl_cert_dir_env_passed_as_capath(self):
        """SSL_CERT_DIR is forwarded as the capath argument."""
        import certifi

        with patch.dict("os.environ", {"SSL_CERT_DIR": "/tmp/certs"}, clear=False):
            os.environ.pop("SSL_CERT_FILE", None)
            os.environ.pop("REQUESTS_CA_BUNDLE", None)

            with patch("descope.http_client.ssl.create_default_context") as mock_ctx_factory:
                mock_ctx_factory.return_value = Mock()

                HTTPClient(project_id="test123", secure=True)

                mock_ctx_factory.assert_called_once_with(
                    cafile=certifi.where(),
                    capath="/tmp/certs",
                )

    def test_requests_ca_bundle_env_loaded_into_context(self):
        """REQUESTS_CA_BUNDLE triggers an extra load_verify_locations call."""
        with patch.dict("os.environ", {"REQUESTS_CA_BUNDLE": "/tmp/extra.pem"}, clear=False):
            os.environ.pop("SSL_CERT_FILE", None)
            os.environ.pop("SSL_CERT_DIR", None)

            with patch("descope.http_client.ssl.create_default_context") as mock_ctx_factory:
                mock_ssl_ctx = Mock()
                mock_ctx_factory.return_value = mock_ssl_ctx

                HTTPClient(project_id="test123", secure=True)

                mock_ssl_ctx.load_verify_locations.assert_called_once_with(cafile="/tmp/extra.pem")

    def test_no_extra_load_when_requests_ca_bundle_unset(self):
        """load_verify_locations is NOT called when REQUESTS_CA_BUNDLE is absent."""
        with patch.dict("os.environ", {}, clear=False):
            os.environ.pop("REQUESTS_CA_BUNDLE", None)

            with patch("descope.http_client.ssl.create_default_context") as mock_ctx_factory:
                mock_ssl_ctx = Mock()
                mock_ctx_factory.return_value = mock_ssl_ctx

                HTTPClient(project_id="test123", secure=True)

                mock_ssl_ctx.load_verify_locations.assert_not_called()

    # ------------------------------------------------------------------ #
    # verify= forwarded to every httpx verb                               #
    # ------------------------------------------------------------------ #

    def _make_success_response(self):
        resp = Mock()
        resp.is_success = True
        resp.status_code = 200
        resp.json.return_value = {}
        return resp

    @patch("httpx.get")
    def test_get_forwards_verify(self, mock_get):
        """GET passes SSLContext (secure) or False (insecure) as verify=."""
        from tests.testutils import SSLMatcher

        mock_get.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=True).get("/x")
        assert mock_get.call_args.kwargs["verify"] == SSLMatcher()

        mock_get.reset_mock()
        mock_get.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=False).get("/x")
        assert mock_get.call_args.kwargs["verify"] == SSLMatcher(insecure=True)

    @patch("httpx.post")
    def test_post_forwards_verify(self, mock_post):
        """POST passes SSLContext (secure) or False (insecure) as verify=."""
        from tests.testutils import SSLMatcher

        mock_post.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=True).post("/x", body={})
        assert mock_post.call_args.kwargs["verify"] == SSLMatcher()

        mock_post.reset_mock()
        mock_post.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=False).post("/x", body={})
        assert mock_post.call_args.kwargs["verify"] == SSLMatcher(insecure=True)

    @patch("httpx.put")
    def test_put_forwards_verify(self, mock_put):
        """PUT passes SSLContext (secure) or False (insecure) as verify=."""
        from tests.testutils import SSLMatcher

        mock_put.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=True).put("/x", body={})
        assert mock_put.call_args.kwargs["verify"] == SSLMatcher()

        mock_put.reset_mock()
        mock_put.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=False).put("/x", body={})
        assert mock_put.call_args.kwargs["verify"] == SSLMatcher(insecure=True)

    @patch("httpx.patch")
    def test_patch_forwards_verify(self, mock_patch):
        """PATCH passes SSLContext (secure) or False (insecure) as verify=."""
        from tests.testutils import SSLMatcher

        mock_patch.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=True).patch("/x", body={})
        assert mock_patch.call_args.kwargs["verify"] == SSLMatcher()

        mock_patch.reset_mock()
        mock_patch.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=False).patch("/x", body={})
        assert mock_patch.call_args.kwargs["verify"] == SSLMatcher(insecure=True)

    @patch("httpx.delete")
    def test_delete_forwards_verify(self, mock_delete):
        """DELETE passes SSLContext (secure) or False (insecure) as verify=."""
        from tests.testutils import SSLMatcher

        mock_delete.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=True).delete("/x")
        assert mock_delete.call_args.kwargs["verify"] == SSLMatcher()

        mock_delete.reset_mock()
        mock_delete.return_value = self._make_success_response()

        HTTPClient(project_id="test123", secure=False).delete("/x")
        assert mock_delete.call_args.kwargs["verify"] == SSLMatcher(insecure=True)

    # ------------------------------------------------------------------ #
    # SSLMatcher self-tests                                                #
    # ------------------------------------------------------------------ #

    def test_ssl_matcher_repr(self):
        from tests.testutils import SSLMatcher

        assert repr(SSLMatcher()) == "SSLMatcher()"
        assert repr(SSLMatcher(insecure=True)) == "SSLMatcher(insecure=True)"

    def test_ssl_matcher_equality(self):
        import ssl

        from tests.testutils import SSLMatcher

        real_ctx = ssl.create_default_context()
        assert SSLMatcher() == real_ctx
        assert not (SSLMatcher() == False)  # noqa: E712
        assert SSLMatcher(insecure=True) == False  # noqa: E712
        assert not (SSLMatcher(insecure=True) == real_ctx)


class TestAsyncModeExperimental(unittest.TestCase):
    @patch("httpx.AsyncClient")
    @patch("httpx.get")
    def test_class_flag_does_not_trigger_async(self, mock_get, mock_async_client):
        """Class-level async_mode_experimental flag is inert; calling get() returns sync response."""
        import asyncio

        mock_response = Mock()
        mock_response.is_success = True
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_get.return_value = mock_response

        client = HTTPClient(project_id="Ptest1234567890123456789", async_mode_experimental=True)
        result = client.get("/test")

        self.assertFalse(asyncio.iscoroutine(result))
        assert isinstance(result, type(mock_response))


class TestAsyncModeGuards(unittest.TestCase):
    """async_mode=True without async_mode_experimental raises AuthException."""

    def _sync_client(self):
        return HTTPClient(project_id="test123")

    def test_get_raises_without_experimental(self):
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException) as cm:
            self._sync_client().get("/path", async_mode=True)
        assert cm.exception.status_code == 400

    def test_post_raises_without_experimental(self):
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException) as cm:
            self._sync_client().post("/path", async_mode=True)
        assert cm.exception.status_code == 400

    def test_put_raises_without_experimental(self):
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException) as cm:
            self._sync_client().put("/path", async_mode=True)
        assert cm.exception.status_code == 400

    def test_patch_raises_without_experimental(self):
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException) as cm:
            self._sync_client().patch("/path", body={}, async_mode=True)
        assert cm.exception.status_code == 400

    def test_delete_raises_without_experimental(self):
        from descope.exceptions import AuthException

        with self.assertRaises(AuthException) as cm:
            self._sync_client().delete("/path", async_mode=True)
        assert cm.exception.status_code == 400


class TestAsyncMethods(unittest.TestCase):
    """Tests for async HTTP methods and aclose()."""

    def _make_mock_response(self, body=None):
        resp = Mock()
        resp.is_success = True
        resp.status_code = 200
        resp.json.return_value = body or {"data": "ok"}
        resp.headers = {"cf-ray": "async123"}
        return resp

    def _async_client_with_mock(self, mock_async_client_class, **verb_mocks):
        from unittest.mock import AsyncMock

        mock_client = Mock()
        for verb, response in verb_mocks.items():
            setattr(mock_client, verb, AsyncMock(return_value=response))
        mock_async_client_class.return_value = mock_client
        return mock_client

    @patch("httpx.AsyncClient")
    def test_async_get(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp = self._make_mock_response()
        mock_client = Mock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        result = asyncio.run(client.get("/path", async_mode=True))

        assert result.status_code == 200
        mock_client.get.assert_awaited_once()

    @patch("httpx.AsyncClient")
    def test_async_get_verbose(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp = self._make_mock_response()
        mock_client = Mock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True, verbose=True)

        async def run():
            await client.get("/path", async_mode=True)
            return client.get_last_response()

        last = asyncio.run(run())
        assert last is not None
        assert last.status_code == 200

    @patch("httpx.AsyncClient")
    def test_async_post(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp = self._make_mock_response()
        mock_client = Mock()
        mock_client.post = AsyncMock(return_value=resp)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        result = asyncio.run(client.post("/path", body={"k": "v"}, async_mode=True))

        assert result.status_code == 200

    @patch("httpx.AsyncClient")
    def test_async_put(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp = self._make_mock_response()
        mock_client = Mock()
        mock_client.put = AsyncMock(return_value=resp)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        result = asyncio.run(client.put("/path", body={"k": "v"}, async_mode=True))

        assert result.status_code == 200

    @patch("httpx.AsyncClient")
    def test_async_put_verbose(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp = self._make_mock_response()
        mock_client = Mock()
        mock_client.put = AsyncMock(return_value=resp)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True, verbose=True)

        async def run():
            await client.put("/path", body={}, async_mode=True)
            return client.get_last_response()

        last = asyncio.run(run())
        assert last is not None

    @patch("httpx.AsyncClient")
    def test_async_patch(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp = self._make_mock_response()
        mock_client = Mock()
        mock_client.patch = AsyncMock(return_value=resp)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        result = asyncio.run(client.patch("/path", body={"k": "v"}, async_mode=True))

        assert result.status_code == 200

    @patch("httpx.AsyncClient")
    def test_async_delete(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp = self._make_mock_response()
        mock_client = Mock()
        mock_client.delete = AsyncMock(return_value=resp)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        result = asyncio.run(client.delete("/path", async_mode=True))

        assert result.status_code == 200

    @patch("httpx.AsyncClient")
    def test_aclose_with_async_client(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        mock_client = Mock()
        mock_client.aclose = AsyncMock()
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        asyncio.run(client.aclose())

        mock_client.aclose.assert_awaited_once()

    def test_aclose_without_async_client(self):
        import asyncio

        client = HTTPClient(project_id="test123")
        asyncio.run(client.aclose())  # no-op, must not raise

    @patch("httpx.AsyncClient")
    def test_async_get_retries_on_503(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock
        from unittest.mock import patch as mock_patch

        resp_503 = Mock()
        resp_503.is_success = False
        resp_503.status_code = 503
        resp_503.aclose = AsyncMock()

        resp_200 = Mock()
        resp_200.is_success = True
        resp_200.status_code = 200
        resp_200.json.return_value = {"ok": True}
        resp_200.headers = {}

        mock_client = Mock()
        mock_client.get = AsyncMock(side_effect=[resp_503, resp_200])
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        with mock_patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = asyncio.run(client.get("/path", async_mode=True))

        assert result.status_code == 200
        assert mock_client.get.await_count == 2
        mock_sleep.assert_awaited_once()

    @patch("httpx.AsyncClient")
    def test_async_get_no_retry_on_non_retryable(self, mock_cls):
        import asyncio
        from unittest.mock import AsyncMock

        resp_404 = Mock()
        resp_404.is_success = False
        resp_404.status_code = 404
        resp_404.text = "not found"

        mock_client = Mock()
        mock_client.get = AsyncMock(return_value=resp_404)
        mock_cls.return_value = mock_client

        client = HTTPClient(project_id="test123", async_mode_experimental=True)
        with self.assertRaises(AuthException):
            asyncio.run(client.get("/path", async_mode=True))

        assert mock_client.get.await_count == 1


class TestVerbosePut(unittest.TestCase):
    @patch("httpx.put")
    def test_verbose_mode_captures_put_response(self, mock_put):
        mock_response = Mock()
        mock_response.is_success = True
        mock_response.json.return_value = {"updated": "user1"}
        mock_response.headers = {"cf-ray": "put123"}
        mock_response.status_code = 200
        mock_put.return_value = mock_response

        client = HTTPClient(project_id="test123", verbose=True)
        client.put("/users/1", body={"name": "updated"})

        last_resp = client.get_last_response()
        assert last_resp is not None
        assert last_resp["updated"] == "user1"
        assert last_resp.status_code == 200


if __name__ == "__main__":
    unittest.main()
