"""E2E test: access key exchange and CRUD."""

import os

import pytest

from descope import AccessKeyLoginOptions
from descope.common import SESSION_TOKEN_NAME

pytestmark = pytest.mark.e2e


class TestE2E_AccessKeys:
    async def test_exchange_access_key(self, descope_client):
        key1_id = None
        key2_id = None
        try:
            # Create AK1 with custom claims and description
            resp1 = await descope_client.invoke(
                descope_client.mgmt.access_key.create(
                    name="AK1",
                    custom_claims={"k1": "v1"},
                    description="hey",
                )
            )
            access_key_cleartext = resp1["cleartext"]
            key1 = resp1["key"]
            key1_id = key1["id"]
            assert key1["permittedIps"] == []
            assert key1["description"] == "hey"

            # Create AK2 with permitted IPs
            resp2 = await descope_client.invoke(
                descope_client.mgmt.access_key.create(
                    name="AK2",
                    custom_claims={"k1": "v1"},
                    permitted_ips=["10.0.0.1", "192.168.1.0/24"],
                )
            )
            key2 = resp2["key"]
            key2_id = key2["id"]
            assert key2["permittedIps"] == ["10.0.0.1", "192.168.1.0/24"]
            assert key2["description"] == ""

            # Exchange AK1 with custom claims in login options
            loc = AccessKeyLoginOptions(custom_claims={"nsec-k1": "nsec-v1"})
            jwt_response = await descope_client.invoke(
                descope_client.exchange_access_key(
                    access_key=access_key_cleartext,
                    login_options=loc,
                )
            )
            assert jwt_response, "exchange_access_key returned empty response"

            token = jwt_response[SESSION_TOKEN_NAME]
            assert token["k1"] == "v1"
            assert token["nsec"] is not None
            assert token["nsec"]["nsec-k1"] == "nsec-v1"
            assert jwt_response["projectId"] == os.environ.get("DESCOPE_PROJECT_ID", "")
        finally:
            if key1_id:
                await descope_client.invoke(descope_client.mgmt.access_key.delete(key1_id))
            if key2_id:
                await descope_client.invoke(descope_client.mgmt.access_key.delete(key2_id))

    async def test_update_access_key(self, descope_client):
        key_id = None
        try:
            # Create
            resp = await descope_client.invoke(descope_client.mgmt.access_key.create(name="AAA", description="hey"))
            key = resp["key"]
            key_id = key["id"]
            assert key["name"] == "AAA"
            assert key["description"] == "hey"

            # Update name and description
            await descope_client.invoke(
                descope_client.mgmt.access_key.update(id=key_id, name="ABA", description="hello there")
            )

            # Load and verify update
            resp = await descope_client.invoke(descope_client.mgmt.access_key.load(key_id))
            key = resp["key"]
            assert key["name"] == "ABA"
            assert key["description"] == "hello there"

            # Update with description=None — existing description must be preserved
            await descope_client.invoke(descope_client.mgmt.access_key.update(id=key_id, name="ABA1", description=None))

            # Load and verify name changed but description unchanged
            resp = await descope_client.invoke(descope_client.mgmt.access_key.load(key_id))
            key = resp["key"]
            assert key["name"] == "ABA1"
            assert key["description"] == "hello there"
        finally:
            if key_id:
                await descope_client.invoke(descope_client.mgmt.access_key.delete(key_id))
