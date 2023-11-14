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
        tag(str): Optional tag for the project. Currently, only the "production" tag is supported.

                                Return value (dict):
        Return dict Containing the new project details (name, id, tag, and settings).

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
