#!/usr/bin/env python3
"""
Example demonstrating the verbose mode feature for capturing HTTP metadata.

This is useful for debugging failed requests by accessing headers like cf-ray,
status codes, and raw response data.
"""

import logging

from descope import AuthException, DescopeClient

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_with_verbose_mode():
    """Example showing how to use verbose mode to capture cf-ray headers for debugging."""

    # Create client with verbose=True to enable response metadata capture
    client = DescopeClient(
        project_id="your-project-id",
        management_key="your-management-key",
        verbose=True,  # Enable verbose mode
    )

    try:
        # Make a management API call
        client.mgmt.user.create(
            login_id="test@example.com",
            email="test@example.com",
            display_name="Test User",
        )

        # Access the last response metadata
        response = client.get_last_response()
        if response:
            logger.info("Request succeeded!")
            logger.info("Status: %s", response.status_code)
            logger.info("cf-ray: %s", response.headers.get("cf-ray"))
            logger.info("x-request-id: %s", response.headers.get("x-request-id"))

    except AuthException:
        # When an error occurs, capture the response metadata for debugging
        response = client.get_last_response()
        if response:
            logger.error("Request failed with status %s", response.status_code)
            logger.error("cf-ray: %s", response.headers.get("cf-ray"))
            logger.error("x-request-id: %s", response.headers.get("x-request-id"))
            logger.error("Response body: %s", response.text)

            # You can now provide cf-ray to Descope support for debugging
            cf_ray = response.headers.get("cf-ray")
            logger.info("Provide this cf-ray to support: %s", cf_ray)

        raise


def example_without_verbose_mode():
    """Example showing default behavior (no metadata captured)."""

    # Default: verbose=False (no metadata captured)
    client = DescopeClient(
        project_id="your-project-id",
        management_key="your-management-key",
        # verbose not specified, defaults to False
    )

    try:
        client.mgmt.user.create(login_id="test@example.com", email="test@example.com")

        # get_last_response() returns None when verbose mode is disabled
        response = client.get_last_response()
        assert response is None

    except AuthException as exc:
        logger.error("Request failed: %s", exc)
        # No metadata available in default mode
        response = client.get_last_response()
        assert response is None


if __name__ == "__main__":
    logger.info("Verbose mode examples:")
    logger.info("\n1. With verbose mode (captures metadata):")
    logger.info("   client = DescopeClient(project_id, management_key, verbose=True)")
    logger.info("   # ... make API calls ...")
    logger.info("   response = client.get_last_response()")
    logger.info("   logger.info(response.headers.get('cf-ray'))")

    logger.info("\n2. Without verbose mode (default, no metadata):")
    logger.info("   client = DescopeClient(project_id, management_key)")
    logger.info("   # ... make API calls ...")
    logger.info("   response = client.get_last_response()  # Returns None")
