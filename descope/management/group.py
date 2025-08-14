from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class Group(HTTPBase):
    def load_all_groups(
        self,
        tenant_id: str,
    ) -> dict:
        """
        Load all groups for a specific tenant id.

        Args:
        tenant_id (str): Tenant ID to load groups from.

        Return value (dict):
        Return dict in the format
             [
                {
                    "id": <group id>,
                    "display": <display name>,
                    "members":[
                        {
                            "loginId": <loginId>,
                            "userId": <userId>,
                            "display": <display name>
                        }
                    ]
                }
            ]
        Containing the loaded groups information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.post(
            MgmtV1.group_load_all_path,
            body={
                "tenantId": tenant_id,
            },
        )
        return response.json()

    def load_all_groups_for_members(
        self,
        tenant_id: str,
        user_ids: Optional[List[str]] = None,
        login_ids: Optional[List[str]] = None,
    ) -> dict:
        """
        Load all groups for the provided user IDs or login IDs.

        Args:
        tenant_id (str): Tenant ID to load groups from.
        user_ids (List[str]): Optional List of user IDs, with the format of "U2J5ES9S8TkvCgOvcrkpzUgVTEBM" (example), which can be found on the user's JWT.
        login_ids (List[str]): Optional List of login IDs, how the users identify when logging in.

        Return value (dict):
        Return dict in the format
             [
                {
                    "id": <group id>,
                    "display": <display name>,
                    "members":[
                        {
                            "loginId": <loginId>,
                            "userId": <userId>,
                            "display": <display name>
                        }
                    ]
                }
            ]
        Containing the loaded groups information.

        Raise:
        AuthException: raised if load operation fails
        """
        user_ids = [] if user_ids is None else user_ids
        login_ids = [] if login_ids is None else login_ids

        response = self._http.post(
            MgmtV1.group_load_all_for_member_path,
            body={
                "tenantId": tenant_id,
                "loginIds": login_ids,
                "userIds": user_ids,
            },
        )
        return response.json()

    def load_all_group_members(
        self,
        tenant_id: str,
        group_id: str,
    ) -> dict:
        """
        Load all members of the provided group id.

        Args:
        tenant_id (str): Tenant ID to load groups from.
        group_id (str): Group ID to load members for.

        Return value (dict):
        Return dict in the format
             [
                {
                    "id": <group id>,
                    "display": <display name>,
                    "members":[
                        {
                            "loginId": <loginId>,
                            "userId": <userId>,
                            "display": <display name>
                        }
                    ]
                }
            ]
        Containing the loaded groups information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.post(
            MgmtV1.group_load_all_group_members_path,
            body={
                "tenantId": tenant_id,
                "groupId": group_id,
            },
        )
        return response.json()
