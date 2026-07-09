"""E2E test: management key CRUD."""

import uuid

import pytest

from descope import MgmtKeyReBac, MgmtKeyStatus

pytestmark = [pytest.mark.e2e, pytest.mark.skip(reason="requires company-level management key permissions")]


class TestE2E_ManagementKey:
    async def test_management_key_crud(self, descope_client):
        key_name = f"test-key-{uuid.uuid4().hex[:10]}"

        # --- Create ---
        rebac = MgmtKeyReBac(company_roles=["company-full-access"])
        create_resp = await descope_client.invoke(
            descope_client.mgmt.management_key.create(
                name=key_name,
                rebac=rebac,
                description="Test management key",
                expires_in=0,
                permitted_ips=["10.0.0.1"],
            )
        )

        assert "key" in create_resp
        assert "cleartext" in create_resp
        key = create_resp["key"]
        key_id = key["id"]
        assert key_id
        assert key["name"] == key_name
        assert key["description"] == "Test management key"
        assert "10.0.0.1" in key["permittedIps"]

        # --- Load ---
        load_resp = await descope_client.invoke(descope_client.mgmt.management_key.load(key_id))
        key = load_resp["key"]
        assert key
        assert key["id"] == key_id
        assert key["name"] == key_name

        # --- Search ---
        search_resp = await descope_client.invoke(descope_client.mgmt.management_key.search())
        keys = search_resp["keys"]
        assert keys
        assert any(k["id"] == key_id for k in keys)

        # --- Update ---
        updated_name = key_name + "_updated"
        update_resp = await descope_client.invoke(
            descope_client.mgmt.management_key.update(
                id=key_id,
                name=updated_name,
                description="Updated test management key",
                permitted_ips=["10.0.0.2"],
                status=MgmtKeyStatus.ACTIVE,
            )
        )
        assert update_resp

        # --- Verify update ---
        verify_resp = await descope_client.invoke(descope_client.mgmt.management_key.load(key_id))
        key = verify_resp["key"]
        assert key["id"] == key_id
        assert key["name"] == updated_name
        assert key["description"] == "Updated test management key"
        assert "10.0.0.2" in key["permittedIps"]

        # --- Delete ---
        delete_resp = await descope_client.invoke(descope_client.mgmt.management_key.delete([key_id]))
        assert delete_resp["total"] == 1
