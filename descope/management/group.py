from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class Group(HTTPBase):
    def load_all_groups(
        self,
        tenant_id: str,
        sso_id: Optional[str] = None,
    ) -> dict:
        """
        Load all groups for a specific tenant id.

        Args:
        tenant_id (str): Tenant ID to load groups from.
        sso_id (str): Optional SSO configuration id (ssoId) to load only groups that came from
            that SSO configuration. Use the reserved id "default_ssoid" for the tenant's default
            SSO configuration. When omitted, all the tenant's groups are returned.

        Return value (dict):
        Return dict in the format
             [
                {
                    "id": <group id>,
                    "display": <display name>,
                    "source": <"scim" or "jit">,
                    "ssoId": <sso configuration id>,
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
        body = {
            "tenantId": tenant_id,
        }
        if sso_id is not None:
            body["ssoId"] = sso_id
        response = self._http.post(
            MgmtV1.group_load_all_path,
            body=body,
        )
        return response.json()

    def load_all_groups_for_members(
        self,
        tenant_id: str,
        user_ids: Optional[List[str]] = None,
        login_ids: Optional[List[str]] = None,
        sso_id: Optional[str] = None,
    ) -> dict:
        """
        Load all groups for the provided user IDs or login IDs.

        Args:
        tenant_id (str): Tenant ID to load groups from.
        user_ids (List[str]): Optional List of user IDs, with the format of "U2J5ES9S8TkvCgOvcrkpzUgVTEBM" (example), which can be found on the user's JWT.
        login_ids (List[str]): Optional List of login IDs, how the users identify when logging in.
        sso_id (str): Optional SSO configuration id (ssoId) to load only groups that came from
            that SSO configuration. Use the reserved id "default_ssoid" for the tenant's default
            SSO configuration. When omitted, all matching groups are returned.

        Return value (dict):
        Return dict in the format
             [
                {
                    "id": <group id>,
                    "display": <display name>,
                    "source": <"scim" or "jit">,
                    "ssoId": <sso configuration id>,
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

        body = {
            "tenantId": tenant_id,
            "loginIds": login_ids,
            "userIds": user_ids,
        }
        if sso_id is not None:
            body["ssoId"] = sso_id
        response = self._http.post(
            MgmtV1.group_load_all_for_member_path,
            body=body,
        )
        return response.json()

    def load_all_group_members(
        self,
        tenant_id: str,
        group_id: str,
        sso_id: Optional[str] = None,
    ) -> dict:
        """
        Load all members of the provided group id.

        Args:
        tenant_id (str): Tenant ID to load groups from.
        group_id (str): Group ID to load members for.
        sso_id (str): Optional SSO configuration id (ssoId): return the group only if it came
            from that SSO configuration. Use the reserved id "default_ssoid" for the tenant's
            default SSO configuration.

        Return value (dict):
        Return dict in the format
             [
                {
                    "id": <group id>,
                    "display": <display name>,
                    "source": <"scim" or "jit">,
                    "ssoId": <sso configuration id>,
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
        body = {
            "tenantId": tenant_id,
            "groupId": group_id,
        }
        if sso_id is not None:
            body["ssoId"] = sso_id
        response = self._http.post(
            MgmtV1.group_load_all_group_members_path,
            body=body,
        )
        return response.json()
