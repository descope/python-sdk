from ssl import SSLContext
from contextlib import contextmanager
from unittest.mock import AsyncMock, Mock, patch


class SSLMatcher:
    def __eq__(self, other):
        return isinstance(other, SSLContext)


@contextmanager
def mock_http_call(
    is_async: bool,
    method: str = "post",
):

    if is_async:
        with _mock_async_http(method) as method_mock:
            yield method_mock
    else:
        with _mock_sync_http(method) as method_mock:
            yield method_mock


@contextmanager
def _mock_sync_http(method: str):
    """Mock synchronous httpx calls."""
    with patch(f"httpx.{method}") as mock_method:
        yield mock_method


@contextmanager
def _mock_async_http(method: str):
    """Mock asynchronous httpx calls."""
    # Create mock client with the specified method
    mock_client = Mock()
    async_method_mock = AsyncMock()
    setattr(mock_client, method, async_method_mock)

    # Mock the async context manager
    mock_async_client = Mock()
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=None)

    # Store references for assertions
    mock_async_client._mock_client = mock_client
    async_method_mock._mock_async_client = mock_async_client

    with patch("httpx.AsyncClient", return_value=mock_async_client) as mock_class:
        # Store the patched class for assertions
        async_method_mock._mock_class = mock_class

        # Override assert_called_with to handle client parameter validation
        original_assert = async_method_mock.assert_called_with

        def enhanced_assert_called_with(*args, **kwargs):
            # Extract client-level parameters
            client_kwargs = {}
            call_kwargs = kwargs.copy()
            if "verify" in call_kwargs:
                client_kwargs["verify"] = call_kwargs.pop("verify")
            if "timeout" in call_kwargs:
                client_kwargs["timeout"] = call_kwargs.pop("timeout")

            # Assert the method call
            original_assert(*args, **call_kwargs)

            # Assert the client creation if client params were provided
            if client_kwargs:
                mock_class.assert_called_with(**client_kwargs)

        async_method_mock.assert_called_with = enhanced_assert_called_with

        # using Mock here to avoid getting AsyncMock as default return value class
        async_method_mock.return_value = Mock()
        yield async_method_mock
