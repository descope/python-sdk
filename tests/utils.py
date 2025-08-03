

import json
from unittest.mock import Mock, patch, AsyncMock
import asyncio

async def safe_await(o): 
    if asyncio.iscoroutine(o) or asyncio.isfuture(o):
        return await o
    return o

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
        
        # Set default json response if not provided
        # if "json" not in response_kwargs:
        #     response_kwargs["json"] = lambda: {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
            
        for key, value in response_kwargs.items():
            if callable(value) and key == "json":
                # Set json as a method that returns the callable result
                mock_response.json = Mock(return_value=value())
                if "text" not in response_kwargs:
                    setattr(mock_response, "text", json.dumps(value()))
            else:
                setattr(mock_response, key, value)

        return patch(f"httpx.{method}", return_value=mock_response)

    @staticmethod
    def _mock_async_http(method: str, **response_kwargs):
        """Mock async httpx calls"""
        mock_response = Mock()
        
        # # Set default json response if not provided
        # if "json" not in response_kwargs:
        #     response_kwargs["json"] = lambda: {"maskedEmail": "m***@example.com", "maskedPhone": "***123"}
            
        for key, value in response_kwargs.items():
            if callable(value) and key == "json":
                # Set json as a method that returns the callable result
                mock_response.json = Mock(return_value=value())
                if "text" not in response_kwargs:
                    setattr(mock_response, "text", json.dumps(value()))
            else:
                setattr(mock_response, key, value)

        # Create a mock async client with the specified method
        mock_client = Mock()
        async_method = AsyncMock(return_value=mock_response)
        setattr(mock_client, method, async_method)
        
        # Mock the async context manager
        mock_async_client = Mock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        
        # Store reference to the mock for assertions
        mock_async_client._mock_client = mock_client
        
        return patch("httpx.AsyncClient", return_value=mock_async_client)

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
            # Get the actual mock client from the context manager
            mock_client = mock_http.return_value._mock_client
            # Find the async method that was called (post, get, etc.)
            for method_name in ['post', 'get', 'put', 'patch', 'delete']:
                if hasattr(mock_client, method_name):
                    method_mock = getattr(mock_client, method_name)
                    if method_mock.called:
                        method_mock.assert_called_with(*args, **call_kwargs)
                        return
        else:
            mock_http.assert_called_with(*args, **call_kwargs)
