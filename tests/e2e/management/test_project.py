"""E2E test: management project capabilities (list + tag update).
Does NOT create or delete projects.
"""

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.skip(reason="requires company-level management key permissions")]


class TestE2E_ManagementProject:
    async def test_management_project_capabilities(self, descope_client):
        list_resp = await descope_client.invoke(descope_client.mgmt.project.list_projects())
        projects = list_resp["projects"]
        assert projects, "Expected at least one project in the list"

        current_tags = projects[0].get("tags", []) if projects else []

        try:
            await descope_client.invoke(descope_client.mgmt.project.update_tags(["e2e-test-tag1", "e2e-test-tag2"]))
        finally:
            await descope_client.invoke(descope_client.mgmt.project.update_tags(current_tags))
