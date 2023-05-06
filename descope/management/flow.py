from typing import List

from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class Flow(AuthBase):
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
        AuthException: raised if creation operation fails
        """
        response = self._auth.do_post(
            MgmtV1.flow_export_path,
            {
                "flowId": flow_id,
            },
            pswd=self._auth.management_key,
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
        AuthException: raised if creation operation fails
        """
        response = self._auth.do_post(
            MgmtV1.flow_import_path,
            {
                "flowId": flow_id,
                "flow": flow,
                "screens": screens,
            },
            pswd=self._auth.management_key,
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
        AuthException: raised if creation operation fails
        """
        response = self._auth.do_post(
            MgmtV1.theme_export_path,
            {},
            pswd=self._auth.management_key,
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
        AuthException: raised if creation operation fails
        """
        response = self._auth.do_post(
            MgmtV1.theme_import_path,
            {
                "theme": theme,
            },
            pswd=self._auth.management_key,
        )
        return response.json()
