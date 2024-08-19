from typing import List, Optional

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
        self._auth.do_post(
            MgmtV1.project_update_tags,
            {
                "tags": tags,
            },
            pswd=self._auth.management_key,
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
        response = self._auth.do_post(
            MgmtV1.project_list_projects,
            {},
            pswd=self._auth.management_key,
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
        response = self._auth.do_post(
            MgmtV1.project_clone,
            {
                "name": name,
                "environment": environment,
                "tags": tags,
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
        self._auth.do_post(
            MgmtV1.project_import,
            {
                "files": files,
            },
            pswd=self._auth.management_key,
        )
        return

    # Function to remove 'tag' field from each project
    def remove_tag_field(self, projects):
        return [
            {k: v for k, v in project.items() if k != "tag"} for project in projects
        ]
