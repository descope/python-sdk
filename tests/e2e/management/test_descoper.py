"""E2E test: descoper (team-member) CRUD."""

import os
import uuid

import pytest

from descope import DescoperAttributes, DescoperCreate, DescoperProjectRole, DescoperRBAC, DescoperRole

pytestmark = [pytest.mark.e2e, pytest.mark.skip(reason="requires company-level management key permissions")]


class TestE2E_ManagementDescoper:
    async def test_descoper_crud(self, descope_client):
        project_id = os.environ.get("DESCOPE_PROJECT_ID", "")
        login_id = f"descoper-{uuid.uuid4()}@example.com"

        # --- Create ---
        attributes = DescoperAttributes(display_name="Test Descoper", email=login_id, phone="+1234567890")
        rbac = DescoperRBAC(projects=[DescoperProjectRole(project_ids=[project_id], role=DescoperRole.DEVELOPER)])
        descoper_create = DescoperCreate(login_id=login_id, attributes=attributes, send_invite=False, rbac=rbac)
        create_resp = await descope_client.invoke(descope_client.mgmt.descoper.create([descoper_create]))

        descopers = create_resp["descopers"]
        assert descopers
        assert len(descopers) == 1
        descoper = descopers[0]
        descoper_id = descoper["id"]
        assert descoper_id
        assert descoper["loginIDs"] == [login_id]

        try:
            # --- Load ---
            load_resp = await descope_client.invoke(descope_client.mgmt.descoper.load(descoper_id))
            loaded = load_resp["descoper"]
            assert loaded
            assert loaded["id"] == descoper_id

            # --- List ---
            list_resp = await descope_client.invoke(descope_client.mgmt.descoper.list())
            descopers_list = list_resp["descopers"]
            assert descopers_list
            assert any(d["id"] == descoper_id for d in descopers_list)

            # --- Update ---
            updated_attributes = DescoperAttributes(
                display_name="Updated Descoper", email=login_id, phone="+0987654321"
            )
            updated_rbac = DescoperRBAC(is_company_admin=True)
            update_resp = await descope_client.invoke(
                descope_client.mgmt.descoper.update(id=descoper_id, attributes=updated_attributes, rbac=updated_rbac)
            )
            assert update_resp

            # --- Verify update ---
            verify_resp = await descope_client.invoke(descope_client.mgmt.descoper.load(descoper_id))
            updated = verify_resp["descoper"]
            assert updated["id"] == descoper_id
            assert updated["attributes"]["displayName"] == "Updated Descoper"
            assert updated["attributes"]["phone"] == "+0987654321"
            assert updated["rbac"]["isCompanyAdmin"]

        finally:
            await descope_client.invoke(descope_client.mgmt.descoper.delete(descoper_id))
