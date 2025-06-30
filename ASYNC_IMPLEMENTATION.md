# Descope Python SDK - Async Support

This document provides information about async/await support in the Descope Python SDK.

## Usage

The SDK supports both synchronous and asynchronous patterns with identical functionality and method signatures.

### Basic Usage

```python
# Synchronous (existing)
from descope import DescopeClient, DeliveryMethod

client = DescopeClient(project_id="P123")
masked_email = client.otp.sign_up(DeliveryMethod.EMAIL, "user@example.com")

# Asynchronous (new) - preferred with context manager
from descope import AsyncDescopeClient, DeliveryMethod

async def main():
    async with AsyncDescopeClient(project_id="P123") as client:
        masked_email = await client.otp.sign_up_async(DeliveryMethod.EMAIL, "user@example.com")

# Or manual resource management
async def main_manual():
    client = AsyncDescopeClient(project_id="P123")
    try:
        masked_email = await client.otp.sign_up_async(DeliveryMethod.EMAIL, "user@example.com")
    finally:
        await client.close_async()
```

### Key Features

- **Zero breaking changes**: All existing synchronous code continues to work unchanged
- **Async method variants**: Every public method has an async variant with `_async` suffix
- **Context manager support**: Use `async with` for automatic resource cleanup
- **Manual cleanup**: Call `close_async()` for manual resource management
- **Identical error handling**: Same exception types and error codes as sync methods
- **Type safety**: Full type hints and IDE support maintained

For complete examples and usage patterns, see the main [README.md](README.md).
