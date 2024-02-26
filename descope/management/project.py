from typing import Optional

from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class Project(AuthBase):
    def update_name(
        self,
        name: str,
    ):
        """
        Update the current project name.

        Args:
        name (str):  The new name for the project.
        Raise:
        AuthException: raised if operation fails
        """
        self._auth.do_post(
            MgmtV1.project_update_name,
            {
                "name": name,
            },
            pswd=self._auth.management_key,
        )

    def clone(
        self,
        name: str,
        tag: Optional[str] = None,
    ):
        """
        Clone the current project, including its settings and configurations.
        - This action is supported only with a pro license or above.
        - Users, tenants and access keys are not cloned.

        Args:
        name (str): The new name for the project.
        tag (str): Optional tag for the project. Currently, only the "production" tag is supported.

        Return value (dict):
        Return dict Containing the new project details (name, id, and tag).

        Raise:
        AuthException: raised if clone operation fails
        """
        response = self._auth.do_post(
            MgmtV1.project_clone,
            {
                "name": name,
                "tag": tag,
            },
            pswd=self._auth.management_key,
        )
        return response.json()

    def export_project(
        self,
    ):
        """
        Exports all settings and configurations for a project and returns the
        raw JSON files response as a dictionary.
        - This action is supported only with a pro license or above.
        - Users, tenants and access keys are not cloned.
        - Secrets, keys and tokens are not stripped from the exported data.

        Return value (dict):
        Return dict Containing the exported JSON files payload.

        Raise:
        AuthException: raised if export operation fails
        """
        response = self._auth.do_post(
            MgmtV1.project_export,
            {},
            pswd=self._auth.management_key,
        )
        return response.json()["files"]

    def import_project(
        self,
        files: dict,
    ):
        """
        Imports all settings and configurations for a project overriding any current
        configuration.
        - This action is supported only with a pro license or above.
        - Secrets, keys and tokens are not overwritten unless overwritten in the input.

        Args:
        files (dict): The raw JSON dictionary of files, in the same format as the one
        returned by calls to export.

        Raise:
        AuthException: raised if import operation fails
        """
        response = self._auth.do_post(
            MgmtV1.project_import,
            {
                "files": files,
            },
            pswd=self._auth.management_key,
        )
        return
