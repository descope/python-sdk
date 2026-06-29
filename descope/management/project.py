from __future__ import annotations

from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class Project(HTTPBase):
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
        self._http.post(
            MgmtV1.project_update_name,
            body={
                "name": name,
            },
        )

    def update_tags(
        self,
        tags: List[str],
    ):
        """
        Update the current project tags.

        Args:
        tags (List[str]):  Array of free text tags.
        Raise:
        AuthException: raised if operation fails
        """
        self._http.post(
            MgmtV1.project_update_tags,
            body={
                "tags": tags,
            },
        )

    def list_projects(
        self,
    ) -> dict:
        """
        List of all the projects in the company.

        Return value (dict):
        Return dict in the format
             {"projects": []}
        "projects" contains a list of all of the projects and their information

        Raise:
        AuthException: raised if operation fails
        """
        response = self._http.post(
            MgmtV1.project_list_projects,
            body={},
        )
        resp = response.json()

        projects = resp["projects"]
        # Apply the function to the projects list
        formatted_projects = self.remove_tag_field(projects)

        # Return the same structure with 'tag' removed
        result = {"projects": formatted_projects}
        return result

    def clone(
        self,
        name: str,
        environment: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ):
        """
        Clone the current project, including its settings and configurations.
        - This action is supported only with a pro license or above.
        - Users, tenants and access keys are not cloned.

        Args:
        name (str): The new name for the project.
        environment (str): Optional state for the project. Currently, only the "production" tag is supported.
        tags(list[str]): Optional free text tags.

        Return value (dict):
        Return dict Containing the new project details (name, id, environment and tag).

        Raise:
        AuthException: raised if clone operation fails
        """
        response = self._http.post(
            MgmtV1.project_clone,
            body={
                "name": name,
                "environment": environment,
                "tags": tags,
            },
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
        response = self._http.post(
            MgmtV1.project_export,
            body={},
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
        self._http.post(
            MgmtV1.project_import,
            body={
                "files": files,
            },
        )
        return

    def delete(self):
        """
        Delete the current project.
        IMPORTANT: This action is irreversible. Use carefully.

        Raise:
        AuthException: raised if delete operation fails
        """
        self._http.post(
            MgmtV1.project_delete_path,
            body={},
        )

    def export_snapshot(
        self,
        format: Optional[str] = None,
    ) -> dict:
        """
        Exports a snapshot of all the settings and configurations for a project and returns
        the raw JSON files response as a dictionary.

        Args:
        format (str): Optional format for the snapshot export.

        Return value (dict):
        Return dict containing the exported snapshot data.

        Raise:
        AuthException: raised if export operation fails
        """
        body = {}
        if format:
            body["format"] = format
        response = self._http.post(
            MgmtV1.project_snapshot_export_path,
            body=body,
        )
        return response.json()

    def import_snapshot(
        self,
        files: dict,
        input_secrets: Optional[dict] = None,
        excludes: Optional[List[str]] = None,
    ):
        """
        Imports a snapshot of all settings and configurations into a project, overriding any
        current configuration.

        Args:
        files (dict): The raw JSON dictionary of files, in the same format as the one
                      returned by calls to export_snapshot.
        input_secrets (dict): Optional secrets that need to be provided for the import.
        excludes (List[str]): Optional list of items to exclude from the import.

        Raise:
        AuthException: raised if import operation fails
        """
        body: dict = {"files": files}
        if input_secrets is not None:
            body["inputSecrets"] = input_secrets
        if excludes is not None:
            body["excludes"] = excludes
        self._http.post(
            MgmtV1.project_snapshot_import_path,
            body=body,
        )

    def validate_snapshot(
        self,
        files: dict,
        input_secrets: Optional[dict] = None,
    ) -> dict:
        """
        Validates a snapshot by performing an import dry run and reporting any validation
        failures or missing data. This should be called right before import_snapshot to
        minimize the risk of the import failing.

        Args:
        files (dict): The raw JSON dictionary of files to validate.
        input_secrets (dict): Optional secrets to provide for validation.

        Return value (dict):
        Return dict containing validation results, including 'ok' boolean and any 'failures'
        or 'missingSecrets' if validation fails.

        Raise:
        AuthException: raised if validation operation fails
        """
        body: dict = {"files": files}
        if input_secrets is not None:
            body["inputSecrets"] = input_secrets
        response = self._http.post(
            MgmtV1.project_snapshot_validate_path,
            body=body,
        )
        return response.json()

    # Function to remove 'tag' field from each project
    def remove_tag_field(self, projects):
        return [{k: v for k, v in project.items() if k != "tag"} for project in projects]
