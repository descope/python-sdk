import asyncio
import json
import unittest
import httpx
from unittest.mock import Mock, patch, AsyncMock, call
from unittest import IsolatedAsyncioTestCase

from .utils import HTTPMockHelper, safe_await


class TestSafeAwait(IsolatedAsyncioTestCase):
    """Test cases for the safe_await function"""

    async def test_safe_await_with_coroutine(self):
        """Test that safe_await properly awaits a coroutine object"""
        async def sample_coroutine():
            return "coroutine_result"
        
        result = await safe_await(sample_coroutine())
        self.assertEqual(result, "coroutine_result")

    async def test_safe_await_with_future(self):
        """Test that safe_await properly awaits a Future object"""
        future = asyncio.Future()
        future.set_result("future_result")
        
        result = await safe_await(future)
        self.assertEqual(result, "future_result")

    async def test_safe_await_with_non_awaitable(self):
        """Test that safe_await returns non-awaitable objects directly"""
        result = await safe_await("simple_string")
        self.assertEqual(result, "simple_string")
        
        result = await safe_await(42)
        self.assertEqual(result, 42)
        
        result = await safe_await({"key": "value"})
        self.assertEqual(result, {"key": "value"})

    async def test_safe_await_with_none(self):
        """Test that safe_await handles None values"""
        result = await safe_await(None)
        self.assertIsNone(result)

    async def test_safe_await_with_exception_in_coroutine(self):
        """Test that safe_await properly propagates exceptions from coroutines"""
        async def failing_coroutine():
            raise ValueError("Test exception")
        
        with self.assertRaises(ValueError) as context:
            await safe_await(failing_coroutine())
        self.assertEqual(str(context.exception), "Test exception")

    async def test_safe_await_with_future_exception(self):
        """Test that safe_await properly propagates exceptions from futures"""
        future = asyncio.Future()
        future.set_exception(RuntimeError("Future exception"))
        
        with self.assertRaises(RuntimeError) as context:
            await safe_await(future)
        self.assertEqual(str(context.exception), "Future exception")


class TestHTTPMockHelper(IsolatedAsyncioTestCase):
    """Test cases for the HTTPMockHelper class"""

    def test_mock_http_call_sync_post_default(self):
        """Test sync POST request with default response"""
        with HTTPMockHelper.mock_http_call(False, "post"):
            # Actually call httpx.post to verify the mock works
            response = httpx.post("http://test.com", json={"test": "data"})
            
            # Verify the mock response has default properties
            expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
            self.assertEqual(response.json(), expected_json)

    def test_mock_http_call_sync_get(self):
        """Test sync GET request"""
        with HTTPMockHelper.mock_http_call(False, "get"):
            # Actually call httpx.get to verify the mock works
            response = httpx.get("http://test.com", params={"param": "value"})
            
            # Verify the mock response has default properties
            expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
            self.assertEqual(response.json(), expected_json)

    def test_mock_http_call_sync_with_custom_json(self):
        """Test sync request with custom json response"""
        custom_json = {"custom": "data", "test": True}
        
        with HTTPMockHelper.mock_http_call(False, "post", json=lambda: custom_json):
            # Actually call httpx.post to verify the mock works
            response = httpx.post("http://test.com", json={"test": "data"})
            
            # Verify the mock response has custom properties
            self.assertEqual(response.json(), custom_json)
            # Verify text is set to JSON string
            self.assertEqual(response.text, json.dumps(custom_json))

    def test_mock_http_call_sync_with_ok_false(self):
        """Test sync request with ok=False"""
        with HTTPMockHelper.mock_http_call(False, "post", ok=False):
            # Actually call httpx.post to verify the mock works
            response = httpx.post("http://test.com", json={"test": "data"})
            
            # Verify the mock response has ok=False
            self.assertEqual(response.ok, False)

    def test_mock_http_call_sync_with_cookies(self):
        """Test sync request with cookies"""
        test_cookies = {"session": "abc123", "refresh": "def456"}
        
        with HTTPMockHelper.mock_http_call(False, "post", cookies=test_cookies):
            # Actually call httpx.post to verify the mock works
            response = httpx.post("http://test.com", json={"test": "data"})
            
            # Verify the mock response has cookies set
            self.assertEqual(response.cookies, test_cookies)

    async def test_mock_http_call_async_post_default(self):
        """Test async POST request with default response"""
        with HTTPMockHelper.mock_http_call(True, "post"):
            # Actually call httpx.AsyncClient to verify the mock works
            async with httpx.AsyncClient() as client:
                response = await client.post("http://test.com", json={"test": "data"})
                
                # Verify the mock response has default properties
                expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
                self.assertEqual(response.json(), expected_json)

    async def test_mock_http_call_async_get(self):
        """Test async GET request"""
        with HTTPMockHelper.mock_http_call(True, "get"):
            # Actually call httpx.AsyncClient to verify the mock works
            async with httpx.AsyncClient() as client:
                response = await client.get("http://test.com", params={"param": "value"})
                
                # Verify the mock response has default properties
                expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
                self.assertEqual(response.json(), expected_json)

    async def test_mock_http_call_async_with_custom_json(self):
        """Test async request with custom json response"""
        custom_json = {"async": "data", "test": True}
        
        with HTTPMockHelper.mock_http_call(True, "post", json=lambda: custom_json):
            # Actually call httpx.AsyncClient to verify the mock works
            async with httpx.AsyncClient() as client:
                response = await client.post("http://test.com", json={"test": "data"})
                
                # Verify the mock response has custom properties
                self.assertEqual(response.json(), custom_json)

    async def test_mock_http_call_async_with_ok_false(self):
        """Test async request with ok=False"""
        with HTTPMockHelper.mock_http_call(True, "post", ok=False):
            # Actually call httpx.AsyncClient to verify the mock works
            async with httpx.AsyncClient() as client:
                response = await client.post("http://test.com", json={"test": "data"})
                
                # Verify the mock response has ok=False
                self.assertEqual(response.ok, False)
                self.assertEqual(response.status_code, 400)

    async def test_mock_http_call_async_with_cookies(self):
        """Test async request with cookies"""
        test_cookies = {"session": "async123", "refresh": "async456"}
        
        with HTTPMockHelper.mock_http_call(True, "post", cookies=test_cookies):
            # Actually call httpx.AsyncClient to verify the mock works
            async with httpx.AsyncClient() as client:
                response = await client.post("http://test.com", json={"test": "data"})
                
                # Verify the mock response has cookies set
                self.assertEqual(response.cookies, test_cookies)

    def test_mock_sync_http_private_method(self):
        """Test _mock_sync_http private method directly"""
        patch_obj = HTTPMockHelper._mock_sync_http("patch")
        self.assertIsNotNone(patch_obj)
        # Verify it returns a patch object
        self.assertEqual(type(patch_obj).__name__, '_patch')
        self.assertEqual(patch_obj.attribute, "patch")

    def test_mock_async_http_private_method(self):
        """Test _mock_async_http private method directly"""
        patch_obj = HTTPMockHelper._mock_async_http("delete")
        self.assertIsNotNone(patch_obj)
        # Verify it returns a patch object
        self.assertEqual(type(patch_obj).__name__, '_patch')
        self.assertEqual(patch_obj.attribute, "AsyncClient")

    def test_assert_http_call_sync_success(self):
        """Test assert_http_call for sync calls with correct parameters"""
        with HTTPMockHelper.mock_http_call(False, "post") as mock_http:
            # Actually call httpx.post
            httpx.post("http://test.com", json={"test": "data"})
            
            # This should not raise an assertion error
            HTTPMockHelper.assert_http_call(
                mock_http, False, "http://test.com", json={"test": "data"}
            )

    def test_assert_http_call_sync_failure(self):
        """Test assert_http_call for sync calls with wrong parameters"""
        with HTTPMockHelper.mock_http_call(False, "post") as mock_http:
            # Actually call httpx.post with specific parameters
            httpx.post("http://test.com", json={"test": "data"})
            
            # This should raise an assertion error because we expect different parameters
            with self.assertRaises(AssertionError):
                HTTPMockHelper.assert_http_call(
                    mock_http, False, "http://different.com", json={"different": "data"}
                )

    async def test_assert_http_call_async_success(self):
        """Test assert_http_call for async calls with correct parameters"""
        with HTTPMockHelper.mock_http_call(True, "post") as mock_http:
            # Actually call httpx.AsyncClient
            async with httpx.AsyncClient() as client:
                await client.post("http://test.com", json={"test": "data"})
            
            # This should not raise an assertion error
            HTTPMockHelper.assert_http_call(
                mock_http, True, "http://test.com", json={"test": "data"}
            )

    async def test_assert_http_call_async_failure(self):
        """Test assert_http_call for async calls with wrong parameters"""
        with HTTPMockHelper.mock_http_call(True, "post") as mock_http:
            # Actually call httpx.AsyncClient with specific parameters
            async with httpx.AsyncClient() as client:
                await client.post("http://test.com", json={"test": "data"})
            
            # This should raise an assertion error because we expect different parameters
            with self.assertRaises(AssertionError):
                HTTPMockHelper.assert_http_call(
                    mock_http, True, "http://different.com", json={"different": "data"}
                )

    async def test_assert_http_call_async_with_verify_timeout_removed(self):
        """Test that verify and timeout are properly removed from async call assertions"""
        with HTTPMockHelper.mock_http_call(True, "post") as mock_http:
            # Actually call httpx.AsyncClient
            async with httpx.AsyncClient() as client:
                await client.post("http://test.com", json={"test": "data"})
            
            # This should succeed even when verify/timeout are in expected call
            HTTPMockHelper.assert_http_call(
                mock_http, True, "http://test.com", 
                json={"test": "data"}, verify=True, timeout=30
            )

    def test_mock_http_call_with_text_property(self):
        """Test that text property is set when json is provided"""
        custom_json = {"message": "test"}
        
        with HTTPMockHelper.mock_http_call(False, "post", json=lambda: custom_json):
            # Actually call httpx.post to verify the mock works
            response = httpx.post("http://test.com", json={"test": "data"})
            
            # Verify the mock response has text set to JSON string
            self.assertEqual(response.text, json.dumps(custom_json))

    def test_mock_http_call_with_explicit_text(self):
        """Test that explicit text property overrides json-generated text"""
        custom_json = {"message": "test"}
        explicit_text = "custom text response"
        
        with HTTPMockHelper.mock_http_call(
            False, "post", json=lambda: custom_json, text=explicit_text
        ):
            # Actually call httpx.post to verify the mock works
            response = httpx.post("http://test.com", json={"test": "data"})
            
            # Verify the mock response uses explicit text, not JSON-generated text
            self.assertEqual(response.text, explicit_text)

    async def test_mock_http_call_async_context_manager(self):
        """Test that async mock properly implements context manager protocol"""
        with HTTPMockHelper.mock_http_call(True, "post"):
            # Test that the async context manager works properly
            async with httpx.AsyncClient() as client:
                response = await client.post("http://test.com", json={"test": "data"})
                
                # Verify the mock response works
                expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
                self.assertEqual(response.json(), expected_json)

    def test_mock_http_call_unsupported_method(self):
        """Test behavior with unsupported HTTP method"""
        # This should raise AttributeError since httpx doesn't have custom_method
        with self.assertRaises(AttributeError):
            with HTTPMockHelper.mock_http_call(False, "custom_method") as mock_http:
                pass


class TestHTTPMockHelperIntegration(IsolatedAsyncioTestCase):
    """Integration tests for HTTPMockHelper"""

    async def test_integration_with_actual_usage_pattern(self):
        """Test the exact usage pattern from test_otp.py"""
        # Test both sync and async patterns
        for is_async in [False, True]:
            with HTTPMockHelper.mock_http_call(
                is_async, "post", ok=True, json=lambda: {"maskedEmail": "t***@example.com"}
            ):
                if is_async:
                    # Test async pattern
                    async with httpx.AsyncClient() as client:
                        response = await client.post("http://test.com", json={"test": "data"})
                        self.assertEqual(response.json(), {"maskedEmail": "t***@example.com"})
                else:
                    # Test sync pattern
                    response = httpx.post("http://test.com", json={"test": "data"})
                    self.assertEqual(response.json(), {"maskedEmail": "t***@example.com"})

    def test_multiple_http_methods_in_sequence(self):
        """Test using different HTTP methods in sequence"""
        methods = ["get", "post", "patch", "delete"]
        
        for method in methods:
            with HTTPMockHelper.mock_http_call(False, method):
                # Actually call the httpx method to verify the mock works
                httpx_method = getattr(httpx, method)
                response = httpx_method("http://test.com", json={"test": "data"})
                
                # Verify the mock response has expected properties
                expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
                self.assertEqual(response.json(), expected_json)

    async def test_async_mode_switching(self):
        """Test switching between sync and async modes"""
        # Test sync mode
        with HTTPMockHelper.mock_http_call(False, "post"):
            response = httpx.post("http://test.com", json={"test": "data"})
            expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
            self.assertEqual(response.json(), expected_json)
        
        # Test async mode
        with HTTPMockHelper.mock_http_call(True, "post"):
            async with httpx.AsyncClient() as client:
                response = await client.post("http://test.com", json={"test": "data"})
                expected_json = {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
                self.assertEqual(response.json(), expected_json)

    def test_json_callable_vs_static(self):
        """Test difference between callable json and static json"""
        # Test with callable json
        def dynamic_json():
            return {"dynamic": "value", "timestamp": 123}
            
        with HTTPMockHelper.mock_http_call(False, "post", json=dynamic_json):
            response = httpx.post("http://test.com", json={"test": "data"})
            self.assertEqual(response.json(), {"dynamic": "value", "timestamp": 123})
        
        # Test with static json (this should work the same way since the helper converts it)
        static_json = {"static": "value"}
        with HTTPMockHelper.mock_http_call(False, "post", json=lambda: static_json):
            response = httpx.post("http://test.com", json={"test": "data"})
            self.assertEqual(response.json(), static_json)


if __name__ == "__main__":
    unittest.main()
