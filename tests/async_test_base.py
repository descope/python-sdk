import asyncio
import json
from unittest.mock import patch, Mock


def parameterized_sync_async_subcase(sync_method: str, async_method: str):
    """
    Decorator that creates a single test method that runs both sync and async variants
    as subcases within a loop using subTest().
    """

    def decorator(test_func):
        def wrapper(self):
            test_cases = [("sync", sync_method, False), ("async", async_method, True)]

            for case_name, method_name, is_async in test_cases:
                with self.subTest(case=case_name, method=method_name):
                    # Call the original test function with the parameters
                    test_func(self, method_name, is_async)

        # Preserve the original function name and docstring
        wrapper.__name__ = test_func.__name__
        wrapper.__doc__ = test_func.__doc__
        return wrapper

    return decorator


class HTTPMockHelper:
    """Helper class for mocking HTTP calls for both sync and async"""

    @staticmethod
    def mock_http_call(is_async: bool, method: str = "post", **response_kwargs):
        """
        Create appropriate HTTP mock based on sync/async mode

        Args:
            is_async: Whether to mock async or sync HTTP calls
            method: HTTP method ('get', 'post', 'patch', 'delete')
            **response_kwargs: Response properties to set
        """
        if is_async:
            return HTTPMockHelper._mock_async_http(method, **response_kwargs)
        else:
            return HTTPMockHelper._mock_sync_http(method, **response_kwargs)

    @staticmethod
    def _mock_sync_http(method: str, **response_kwargs):
        """Mock sync httpx calls"""
        mock_response = Mock()
        for key, value in response_kwargs.items():
            if callable(value) and key == "json" and "text" not in response_kwargs:
                setattr(mock_response, "text", json.dumps(value()))
            setattr(mock_response, key, value)

        return patch(f"httpx.{method}", return_value=mock_response)

    @staticmethod
    def _mock_async_http(method: str, **response_kwargs):
        """Mock async httpx calls"""
        mock_response = Mock()
        for key, value in response_kwargs.items():
            if callable(value) and key == "json" and "text" not in response_kwargs:
                setattr(mock_response, "text", json.dumps(value()))
            setattr(mock_response, key, value)

        # Mock the async client method to return the mock response
        async def async_mock_method(*args, **kwargs):
            return mock_response

        return patch(f"httpx.AsyncClient.{method}", side_effect=async_mock_method)

    @staticmethod
    def assert_http_call(mock_http, is_async: bool, *args, **kwargs):
        """
        Assert HTTP call was made with expected parameters, handling sync/async differences
        """
        call_kwargs = kwargs.copy()
        if is_async:
            # For async calls, verify/timeout are set on AsyncClient, not on the method call
            call_kwargs.pop("verify", None)
            call_kwargs.pop("timeout", None)
        mock_http.assert_called_with(*args, **call_kwargs)


class MethodTestHelper:
    """Helper to call sync/async methods uniformly in tests"""

    @staticmethod
    def call_method(instance, method_name: str, *args, **kwargs):
        try:
            method = getattr(instance, method_name)
        except AttributeError as e:
            raise AttributeError(
                f"Method '{method_name}' not found on {type(instance).__name__}"
            ) from e
        if MethodTestHelper.is_method_async(instance, method_name):
            # For async methods, we need to run them in the event loop
            return asyncio.run(method(*args, **kwargs))
        else:
            return method(*args, **kwargs)

    @staticmethod
    def is_method_async(instance, method_name: str) -> bool:
        try:
            method = getattr(instance, method_name)
            return asyncio.iscoroutinefunction(method)
        except AttributeError:
            return False
