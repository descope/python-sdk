"""
Async support for Descope SDK.

Provides a native AsyncDescopeClient class that mirrors DescopeClient structure
but with async methods throughout.
"""

from __future__ import annotations

from typing import Any, Callable, TypeVar

from asyncer import asyncify as _asyncify

from descope.common import DEFAULT_TIMEOUT_SECONDS

T = TypeVar("T")


def _add_async_methods(cls: type[T], method_suffix: str = "_async") -> type[T]:
    """
    Monkey patch a class to add async versions of all public methods.

    Args:
        cls: The class to patch
        method_suffix: Suffix to add to async method names

    Returns:
        The same class with async methods added
    """
    # Find all public methods
    for name in dir(cls):
        attr = getattr(cls, name)
        if (
            not name.startswith("_")
            and callable(attr)
            and not isinstance(attr, property)
            and not name.endswith(method_suffix)
        ):  # Don't patch already async methods
            async_method_name = f"{name}{method_suffix}"

            # Create async wrapper
            async_method = _create_async_wrapper(attr, name)

            # Add to class
            setattr(cls, async_method_name, async_method)

    return cls


def _create_async_wrapper(original_method: Callable, method_name: str) -> Callable:
    """Create an async wrapper for a method."""

    async def async_wrapper(self, *args, **kwargs):
        """Async wrapper that runs the sync method in a thread."""
        # Get the bound method from self
        bound_method = getattr(self, method_name)
        return await _asyncify(bound_method)(*args, **kwargs)

    # Preserve method signature and docstring
    async_wrapper.__name__ = f"{method_name}_async"

    # Try to set __qualname__ safely (may fail with mocks)
    try:
        if hasattr(original_method, "__qualname__"):
            async_wrapper.__qualname__ = f"{original_method.__qualname__}_async"
    except (AttributeError, TypeError):
        # Skip if __qualname__ is not accessible (e.g., with mocks)
        pass

    # Try to set docstring safely
    try:
        if hasattr(original_method, "__doc__") and original_method.__doc__:
            async_wrapper.__doc__ = (
                f"Async version of {method_name}.\n\n{original_method.__doc__}"
            )
        else:
            async_wrapper.__doc__ = f"Async version of {method_name}."
    except (AttributeError, TypeError):
        # Skip if __doc__ is not accessible
        async_wrapper.__doc__ = f"Async version of {method_name}."

    return async_wrapper


def _asyncify_client(client_instance: Any) -> Any:
    """
    Add async methods to an existing client instance.

    Args:
        client_instance: Any client instance (DescopeClient, OTP, etc.)

    Returns:
        The same instance with async methods added
    """
    # Patch the instance's class
    _add_async_methods(client_instance.__class__)

    # Recursively patch all authentication method attributes
    # Use a safe list of known auth method attributes to avoid triggering properties
    auth_method_attrs = [
        "otp",
        "magiclink",
        "enchantedlink",
        "oauth",
        "saml",
        "sso",
        "totp",
        "webauthn",
        "password",
        "passkey",
        "flow",
        "notp",
        "audit",
        "authz",
        "permission",
        "role",
        "tenant",
        "user",
        "access_key",
        "project",
        "jwt",
        "session",
        "mgmt",
    ]

    for attr_name in auth_method_attrs:
        # Special handling for mgmt property which raises exception without management key
        if attr_name == "mgmt":
            try:
                if hasattr(client_instance, attr_name):
                    attr = getattr(client_instance, attr_name)
                    # For mgmt, we'd need to patch each sub-module, but skip for now
                    # since management operations are less commonly used in async contexts
                    pass
            except Exception:
                # Skip mgmt if management key not provided
                continue
        else:
            if hasattr(client_instance, attr_name):
                try:
                    attr = getattr(client_instance, attr_name)
                    if hasattr(attr, "__class__") and hasattr(attr, "_auth"):
                        # This looks like an auth method class
                        _add_async_methods(attr.__class__)
                except Exception:
                    # Skip attributes that can't be accessed safely
                    continue

    return client_instance


class AsyncDescopeClient:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: str,
        public_key: dict | None = None,
        skip_verify: bool = False,
        management_key: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        jwt_validation_leeway: int = 5,
    ):
        # Import here to avoid circular import
        from .descope_client import DescopeClient

        # Create a sync client instance
        self._sync_client = DescopeClient(
            project_id,
            public_key,
            skip_verify,
            management_key,
            timeout_seconds,
            jwt_validation_leeway,
        )

        # Patch it with async methods
        _asyncify_client(self._sync_client)

    def __getattr__(self, name):
        """Dynamically delegate all attribute access to the sync client."""
        attr = getattr(self._sync_client, name)

        # If it's a method and we have an async version, prefer the async version
        if callable(attr) and hasattr(self._sync_client, f"{name}_async"):
            return getattr(self._sync_client, f"{name}_async")

        return attr

    async def close(self):
        """Close the client and clean up resources."""
        # For now, this is just a placeholder since the sync client doesn't have cleanup
        # In the future, this could close async HTTP connections
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
