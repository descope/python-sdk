from typing import List, Optional, Union

from descope._http_base import HTTPBase
from descope.management.common import FlowRunOptions, MgmtV1


class Flow(HTTPBase):
    def list_flows(
        self,
    ) -> dict:
        """
        List all project flows

        Return value (dict):
        Return dict in the format
            { "flows": [{"id": "", "name": "", "description": "", "disabled": False}], total: number}

        Raise:
        AuthException: raised if list operation fails
        """
        response = self._http.post(MgmtV1.flow_list_path)
        return response.json()

    def delete_flows(
        self,
        flow_ids: List[str],
    ) -> dict:
        """
        Delete flows by the given ids

        Args:
        flow_ids (List[str]): list of flow IDs to delete.

        Raise:
        AuthException: raised if delete operation fails
        """
        response = self._http.post(
            MgmtV1.flow_delete_path,
            body={
                "ids": flow_ids,
            },
        )
        return response.json()

    def export_flow(
        self,
        flow_id: str,
    ) -> dict:
        """
        Export the given flow id flow and screens.

        Args:
        flow_id (str): the flow id to export.

        Return value (dict):
        Return dict in the format
            { "flow": {"id": "", "name": "", "description": "", "disabled": False, "etag": "", "dsl": {}}, screens: [{ "id": "", "inputs": [], "interactions": [] }] }

        Raise:
        AuthException: raised if export operation fails
        """
        response = self._http.post(
            MgmtV1.flow_export_path,
            body={
                "flowId": flow_id,
            },
        )
        return response.json()

    def import_flow(
        self,
        flow_id: str,
        flow: dict,
        screens: List[dict],
    ) -> dict:
        """
        Import the given flow and screens to the flow id.
        Imoprtant: This will override the current project flow by the given id, treat with caution.

        Args:
        flow_id (str): the flow id to import to.
        flow (dict): the flow to import. dict in the format
            { "flow": {"id": "", "name": "", "description": "", "disabled": False, "etag": "", "dsl": {}}
        screens (List[dict]): the flow screens to import. list of dictss in the format:
            { "id": "", "inputs": [], "interactions": [] }

        Return value (dict):
        Return dict in the format
            { "flow": {"id": "", "name": "", "description": "", "disabled": False, "etag": "", "dsl": {}}, screens: [{ "id": "", "inputs": [], "interactions": [] }] }

        Raise:
        AuthException: raised if import operation fails
        """
        response = self._http.post(
            MgmtV1.flow_import_path,
            body={
                "flowId": flow_id,
                "flow": flow,
                "screens": screens,
            },
        )
        return response.json()

    def export_theme(
        self,
    ) -> dict:
        """
        Export the current project theme.

        Return value (dict):
        Return dict in the format
            {"id": "", "cssTemplate": {} }

        Raise:
        AuthException: raised if export operation fails
        """
        response = self._http.post(
            MgmtV1.theme_export_path,
            body={},
        )
        return response.json()

    def import_theme(
        self,
        theme: dict,
    ) -> dict:
        """
        Import the given theme as the current project theme.
        Imoprtant: This will override the current project theme, treat with caution.

        Args:
        theme (Theme): the theme to import. dict in the format
            {"id": "", "cssTemplate": {} }

        Return value (dict):
        Return dict in the format
            {"id": "", "cssTemplate": {} }

        Raise:
        AuthException: raised if import operation fails
        """
        response = self._http.post(
            MgmtV1.theme_import_path,
            body={
                "theme": theme,
            },
        )
        return response.json()

    def run_flow(
        self,
        flow_id: str,
        options: Optional[Union[FlowRunOptions, dict]] = None,
    ) -> dict:
        """
        Run a flow with the given flow id and options.

        Args:
        flow_id (str): the flow id to run.
        options (Optional[Union[FlowRunOptions, dict]]): optional flow run options containing:
            - input: optional input data to pass to the flow.
            - preview: optional flag to run the flow in preview mode.
            - tenant: optional tenant ID to run the flow for.

        Return value (dict):
        Return dict with the flow execution result.

        Raise:
        AuthException: raised if run operation fails
        """
        body: dict = {"flowId": flow_id}

        if options is not None:
            if isinstance(options, dict):
                options = FlowRunOptions.from_dict(options)
            if options is not None:
                body.update(options.to_dict())

        response = self._http.post(
            MgmtV1.flow_run_path,
            body=body,
        )
        return response.json()

    def run_flow_async(
        self,
        flow_id: str,
        options: Optional[Union[FlowRunOptions, dict]] = None,
    ) -> dict:
        """
        Run a flow asynchronously with the given flow id and options.

        Args:
        flow_id (str): the flow id to run.
        options (Optional[Union[FlowRunOptions, dict]]): optional flow run options containing:
            - input: optional input data to pass to the flow.
            - preview: optional flag to run the flow in preview mode.
            - tenant: optional tenant ID to run the flow for.

        Return value (dict):
        Return dict with the async flow execution result.
        use the get_flow_async_result() method with this result's executionId
        to get the actual flow's result.

        Raise:
        AuthException: raised if run operation fails
        """
        body: dict = {"flowId": flow_id}

        if options is not None:
            if isinstance(options, dict):
                options = FlowRunOptions.from_dict(options)
            if options is not None:
                body.update(options.to_dict())

        response = self._http.post(
            MgmtV1.flow_async_run_path,
            body=body,
        )
        return response.json()

    def get_flow_async_result(
        self,
        execution_id: str,
    ) -> dict:
        """
        Get the result of an async flow execution.

        Args:
        execution_id (str): the execution id returned from run_flow_async.

        Return value (dict):
        Return dict with the async flow execution result.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._http.post(
            MgmtV1.flow_async_result_path,
            body={"executionId": execution_id},
        )
        return response.json()
