"""E2E test: list flows."""

import pytest

pytestmark = pytest.mark.e2e


class TestE2E_ListFlows:
    async def test_list_flows(self, descope_client):
        flows_resp = await descope_client.invoke(descope_client.mgmt.flow.list_flows())
        flows = flows_resp["flows"]
        total = flows_resp["total"]
        assert total == len(flows)
        assert total > 0
