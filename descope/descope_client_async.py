"""
Monkey-patch async support for Descope SDK.

This mod    async_wrapper = _asyncify(original_method)
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

    # Try to preserve the signature safely (skip for now due to asyncer limitations)
    # try:
    #     sig = inspect.signature(original_method)
    #     if hasattr(async_wrapper, "__signature__"):
    #         async_wrapper.__signature__ = sig
    # except (ValueError, TypeError, AttributeError):
    #     passcky but elegant way to add async methods to existing
sync classes without code duplication. It dynamically discovers all public methods
and creates async variants using asyncer.
"""

from __future__ import annotations

from typing import Any, Callable, Type, TypeVar
from asyncer import asyncify as _asyncify

T = TypeVar("T")


def add_async_methods(cls: Type[T], method_suffix: str = "_async") -> Type[T]:
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

    # Try to preserve the signature (skip for now due to asyncer limitations)
    # try:
    #     sig = inspect.signature(original_method)
    #     if hasattr(async_wrapper, "__signature__"):
    #         async_wrapper.__signature__ = sig
    # except (ValueError, TypeError, AttributeError):
    #     pass

    return async_wrapper


def asyncify_client(client_instance: Any) -> Any:
    """
    Add async methods to an existing client instance.

    Args:
        client_instance: Any client instance (DescopeClient, OTP, etc.)

    Returns:
        The same instance with async methods added
    """
    # Patch the instance's class
    add_async_methods(client_instance.__class__)

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
                        add_async_methods(attr.__class__)
                except Exception:
                    # Skip attributes that can't be accessed safely
                    continue

    # Add specific async methods for client-level operations
    _add_client_async_methods(client_instance)

    return client_instance


def _add_client_async_methods(client_instance: Any) -> None:
    """Add client-specific async methods like close_async."""

    async def close_async(self):
        """Async method to close the client and clean up resources."""
        # For now, this is just a placeholder since the sync client doesn't have cleanup
        # In the future, this could close async HTTP connections
        pass

    # Add context manager support
    async def __aenter__(self):  # noqa: N807
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):  # noqa: N807
        """Async context manager exit."""
        await self.close_async()

    # Add methods to the class rather than instance for proper protocol support
    cls = client_instance.__class__

    # Only add if not already present
    if not hasattr(cls, "close_async"):
        cls.close_async = close_async
    if not hasattr(cls, "__aenter__"):
        cls.__aenter__ = __aenter__
    if not hasattr(cls, "__aexit__"):
        cls.__aexit__ = __aexit__


def create_async_client(client_class: Type[T], *args, **kwargs) -> T:
    """
    Create a client instance with async methods automatically added.

    Args:
        client_class: The client class to instantiate
        *args: Arguments for client constructor
        **kwargs: Keyword arguments for client constructor

    Returns:
        Client instance with async methods
    """
    # Create instance
    instance = client_class(*args, **kwargs)

    # Add async methods
    return asyncify_client(instance)


# Convenience function for DescopeClient
def create_async_descope_client(*args, **kwargs):  # noqa: N802
    """
    Create a DescopeClient with async methods added.

    Same signature as DescopeClient but with async methods available.
    All methods get an _async suffix (e.g., sign_up_async, verify_async).

    Example:
        client = create_async_descope_client(project_id="P123")

        # Use sync methods normally
        result = client.otp.sign_up(DeliveryMethod.EMAIL, "user@example.com")

        # Use async methods with _async suffix
        result = await client.otp.sign_up_async(DeliveryMethod.EMAIL, "user@example.com")
    """
    from .descope_client import DescopeClient

    return create_async_client(DescopeClient, *args, **kwargs)


# Alias for convenience (ignore naming convention for this public API)
AsyncDescopeClient = create_async_descope_client  # noqa: N816
