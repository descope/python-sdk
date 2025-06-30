#!/usr/bin/env python3
"""
Descope Async Demo Application

This sample demonstrates how to use the Descope Python SDK with async/await support.
The async client provides the same functionality as the sync client but with async methods
that have an '_async' suffix.

Features demonstrated:
- Async OTP authentication flow (sign up, sign in, verify)
- Context manager usage for automatic resource cleanup
- Manual resource management
- Error handling with async methods
- Management API operations (async)

Prerequisites:
- Set DESCOPE_PROJECT_ID environment variable
- Set DESCOPE_MANAGEMENT_KEY environment variable (for management operations)
- Install dependencies: pip install asyncio aiohttp

Run: python async_demo_app.py
"""

import asyncio
import os
import sys
from typing import Optional

from descope import AsyncDescopeClient, DeliveryMethod, AuthException


class AsyncDescopeDemo:
    """Demo class showcasing async Descope operations."""

    def __init__(self, project_id: str, management_key: Optional[str] = None):
        """
        Initialize the demo.

        Args:
            project_id: Descope project ID
            management_key: Optional management key for admin operations
        """
        self.project_id = project_id
        self.management_key = management_key

    async def run_auth_flow_demo(self):
        """Demonstrate async authentication flow with context manager."""
        print("\n=== Async Authentication Flow Demo ===")

        # Using async context manager (recommended)
        async with AsyncDescopeClient(project_id=self.project_id) as client:
            try:
                # Step 1: Sign up with OTP
                email = "demo@example.com"
                print(f"📧 Starting OTP sign up for: {email}")

                masked_email = await client.otp.sign_up_async(
                    DeliveryMethod.EMAIL,
                    email,
                    user={"name": "Demo User", "email": email},
                )
                print(f"✅ OTP sent to: {masked_email}")

                # Step 2: Simulate OTP verification
                print("🔐 In a real app, user would enter the OTP code here")
                print("    For demo purposes, we'll show how to call verify_code_async")

                # Note: This would normally use the actual OTP code from user input
                demo_code = "123456"  # Placeholder - would fail in real usage
                print(f"📱 Attempting to verify code: {demo_code}")

                try:
                    jwt_response = await client.otp.verify_code_async(
                        DeliveryMethod.EMAIL, email, demo_code
                    )
                    print("✅ Code verified successfully!")
                    print(f"   Session token: {jwt_response.session_token[:20]}...")
                except AuthException as e:
                    print(
                        f"❌ Verification failed (expected with demo code): {e.error_message}"
                    )

                # Step 3: Demonstrate sign in flow
                print(f"\n📧 Starting OTP sign in for: {email}")
                masked_email = await client.otp.sign_in_async(
                    DeliveryMethod.EMAIL, email
                )
                print(f"✅ OTP sent to: {masked_email}")

            except AuthException as e:
                print(f"❌ Authentication error: {e.error_message}")
            except Exception as e:
                print(f"❌ Unexpected error: {e}")

    async def run_manual_cleanup_demo(self):
        """Demonstrate manual resource management."""
        print("\n=== Manual Resource Management Demo ===")

        # Manual resource management
        client = AsyncDescopeClient(project_id=self.project_id)

        try:
            print("🔧 Client created - managing resources manually")

            # Perform some operations
            email = "manual@example.com"
            masked_email = await client.otp.sign_up_async(
                DeliveryMethod.EMAIL, email, user={"name": "Manual Demo User"}
            )
            print(f"✅ Manual OTP sent to: {masked_email}")

        except AuthException as e:
            print(f"❌ Authentication error: {e.error_message}")
        finally:
            # Always clean up resources
            await client.close_async()
            print("🧹 Resources cleaned up manually")

    async def run_session_management_demo(self):
        """Demonstrate async session management operations."""
        print("\n=== Async Session Management Demo ===")

        async with AsyncDescopeClient(project_id=self.project_id) as client:
            try:
                # Demonstrate session validation with a dummy token
                dummy_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImp0aSI6ImVkOGEzMzY3LTU4ZDMtNGM0YS05Mzk0LWY5NjE1MjhkNmY4ZCIsImlhdCI6MTU5NDA3OTAzMCwiZXhwIjoyNDk0MDc5MDMwfQ.invalid"

                print("🔐 Testing session validation (will fail with dummy token)")
                try:
                    session_info = await client.validate_session_async(dummy_token)
                    print(f"✅ Session validated: {session_info}")
                except AuthException as e:
                    print(f"❌ Session validation failed (expected): {e.error_message}")

                # Demonstrate refresh session (will also fail but shows the pattern)
                print("🔄 Testing session refresh (will fail with dummy token)")
                try:
                    refreshed = await client.refresh_session_async(dummy_token)
                    print(f"✅ Session refreshed: {refreshed}")
                except AuthException as e:
                    print(f"❌ Session refresh failed (expected): {e.error_message}")

                # Show available async methods
                print("\n� Available async client methods:")
                async_methods = [
                    attr for attr in dir(client) if attr.endswith("_async")
                ]
                for method in sorted(async_methods):
                    print(f"   🔧 {method}")

            except Exception as e:
                print(f"❌ Unexpected error: {e}")

    async def run_error_handling_demo(self):
        """Demonstrate error handling with async methods."""
        print("\n=== Async Error Handling Demo ===")

        async with AsyncDescopeClient(project_id="invalid-project-id") as client:
            try:
                # This should fail with invalid project ID
                await client.otp.sign_up_async(DeliveryMethod.EMAIL, "test@example.com")
            except AuthException as e:
                print("✅ Caught expected AuthException:")
                print(f"   Status: {e.status_code}")
                print(f"   Type: {e.error_type}")
                print(f"   Message: {e.error_message}")
            except Exception as e:
                print(f"❌ Unexpected error type: {type(e).__name__}: {e}")

    async def run_all_demos(self):
        """Run all demo scenarios."""
        print("🚀 Starting Descope Async SDK Demo")
        print(f"📋 Project ID: {self.project_id}")
        print(
            f"🔑 Management Key: {'✅ Provided' if self.management_key else '❌ Not provided'}"
        )

        await self.run_auth_flow_demo()
        await self.run_manual_cleanup_demo()
        await self.run_session_management_demo()
        await self.run_error_handling_demo()

        print("\n🎉 Demo completed!")


async def main():
    """Main demo function."""
    # Get configuration from environment
    project_id = os.getenv("DESCOPE_PROJECT_ID")
    management_key = os.getenv("DESCOPE_MANAGEMENT_KEY")

    if not project_id:
        print("❌ Error: DESCOPE_PROJECT_ID environment variable is required")
        print("   Export your project ID: export DESCOPE_PROJECT_ID='P123...'")
        sys.exit(1)

    # Create and run demo
    demo = AsyncDescopeDemo(project_id, management_key)
    await demo.run_all_demos()


def sync_demo_comparison():
    """Show comparison between sync and async usage patterns."""
    print("\n=== Sync vs Async Comparison ===")

    sync_example = """
# Synchronous approach (existing)
from descope import DescopeClient, DeliveryMethod

def sync_auth():
    client = DescopeClient(project_id="P123")
    masked_email = client.otp.sign_up(DeliveryMethod.EMAIL, "user@example.com")
    return masked_email
"""

    async_example = """
# Asynchronous approach (new)
from descope import AsyncDescopeClient, DeliveryMethod

async def async_auth():
    async with AsyncDescopeClient(project_id="P123") as client:
        masked_email = await client.otp.sign_up_async(DeliveryMethod.EMAIL, "user@example.com")
        return masked_email
"""

    print("📄 Synchronous code:")
    print(sync_example)
    print("📄 Asynchronous code:")
    print(async_example)

    print("Key differences:")
    print("✨ Async methods have '_async' suffix")
    print("✨ Use 'await' keyword before method calls")
    print("✨ Use 'async with' context manager for resource management")
    print("✨ Same error handling and return types")


if __name__ == "__main__":
    print("=" * 60)
    print("🎯 Descope Python SDK - Async Demo Application")
    print("=" * 60)

    # Show sync vs async comparison
    sync_demo_comparison()

    try:
        # Run async demo
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        sys.exit(1)
