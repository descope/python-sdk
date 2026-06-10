import pytest

from descope import AuthException
from descope.management.common import FlowRunOptions, MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestFlow:
    async def test_list_flows(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.list_flows())

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.list_flows())
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_list_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json=None,
                follow_redirects=False,
            )

    async def test_delete_flows(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed delete flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.delete_flows(["flow-1", "flow-2"]))

        # Test success delete flows
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.delete_flows(["flow-1", "flow-2"]))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"ids": ["flow-1", "flow-2"]},
                follow_redirects=False,
            )

    async def test_export_flow(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.export_flow("name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.export_flow("test"))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_export_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"flowId": "test"},
                follow_redirects=False,
            )

    async def test_import_flow(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.import_flow("name", {"name": "test"}, [{"id": "test"}]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.import_flow("name", {"name": "test"}, [{"id": "test"}]))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_import_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "flowId": "name",
                    "flow": {"name": "test"},
                    "screens": [{"id": "test"}],
                },
                follow_redirects=False,
            )

    async def test_export_theme(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.export_theme())

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.export_theme())
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.theme_export_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={},
                follow_redirects=False,
            )

    async def test_import_theme(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.import_theme({"id": "test"}))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.import_theme({"id": "test"}))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.theme_import_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"theme": {"id": "test"}},
                follow_redirects=False,
            )

    async def test_run_flow(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed run flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.run_flow("test-flow"))

        # Test success run flow with no options
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.run_flow("test-flow"))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_run_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"flowId": "test-flow"},
                follow_redirects=False,
            )

        # Test success run flow with dict options
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.flow.run_flow(
                    "test-flow",
                    {"input": {"key": "value"}, "preview": True, "tenant": "tenant-id"},
                )
            )
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_run_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "flowId": "test-flow",
                    "input": {"key": "value"},
                    "preview": True,
                    "tenant": "tenant-id",
                },
                follow_redirects=False,
            )

        # Test success run flow with FlowRunOptions object
        with client.mock_mgmt_post(make_response()) as mock_post:
            options = FlowRunOptions(
                flow_input={"key": "value"},
                preview=True,
                tenant="tenant-id",
            )
            result = await client.invoke(client.mgmt.flow.run_flow("test-flow", options))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_run_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "flowId": "test-flow",
                    "input": {"key": "value"},
                    "preview": True,
                    "tenant": "tenant-id",
                },
                follow_redirects=False,
            )

    async def test_flow_run_options_from_dict(self, client_factory):
        # Test from_dict with None returns None
        assert FlowRunOptions.from_dict(None) is None

        # Test from_dict with valid dict
        options = FlowRunOptions.from_dict({"input": {"key": "value"}, "preview": True, "tenant": "tenant-id"})
        assert options is not None
        assert options.flow_input == {"key": "value"}
        assert options.preview == True
        assert options.tenant == "tenant-id"

    async def test_run_flow_async(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed run flow async
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.run_flow_async("test-flow"))

        # Test success run flow async with no options
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.run_flow_async("test-flow"))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_async_run_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"flowId": "test-flow"},
                follow_redirects=False,
            )

        # Test success run flow async with dict options
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(
                client.mgmt.flow.run_flow_async(
                    "test-flow",
                    {"input": {"key": "value"}, "preview": True, "tenant": "tenant-id"},
                )
            )
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_async_run_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "flowId": "test-flow",
                    "input": {"key": "value"},
                    "preview": True,
                    "tenant": "tenant-id",
                },
                follow_redirects=False,
            )

        # Test success run flow async with FlowRunOptions object
        with client.mock_mgmt_post(make_response()) as mock_post:
            options = FlowRunOptions(
                flow_input={"key": "value"},
                preview=True,
                tenant="tenant-id",
            )
            result = await client.invoke(client.mgmt.flow.run_flow_async("test-flow", options))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_async_run_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "flowId": "test-flow",
                    "input": {"key": "value"},
                    "preview": True,
                    "tenant": "tenant-id",
                },
                follow_redirects=False,
            )

    async def test_get_flow_async_result(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed get flow async result
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.flow.get_flow_async_result("execution-123"))

        # Test success get flow async result
        with client.mock_mgmt_post(make_response()) as mock_post:
            result = await client.invoke(client.mgmt.flow.get_flow_async_result("execution-123"))
            assert result is not None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_async_result_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"executionId": "execution-123"},
                follow_redirects=False,
            )
