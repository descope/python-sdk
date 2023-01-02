from typing import List

from descope.auth import Auth
from descope.management.common import MgmtV1


class Group:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

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
                            "identifier": <identifier>,
                            "jwtSubject": <jwtSubject>,
                            "display": <display name>
                        }
                    ]
                }
            ]
        Containing the loaded groups information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_post(
            MgmtV1.groupLoadAllPath,
            {
                "tenantId": tenant_id,
            },
            pswd=self._auth.management_key,
        )
        return response.json()

    def load_all_groups_for_members(
        self,
        tenant_id: str,
        jwt_subjects: List[str] = [],
        identifiers: List[str] = [],
    ) -> dict:
        """
        Load all groups for the provided user JWT subjects or identifiers.

        Args:
        tenant_id (str): Tenant ID to load groups from.
        jwt_subjects (List[str]): List of JWT subjects, with the format of "U2J5ES9S8TkvCgOvcrkpzUgVTEBM" (example), which can be found on the user's JWT.
        identifiers (List[str]): List of identifiers, identifier is the actual user identifier used for sign in.

        Return value (dict):
        Return dict in the format
             [
                {
                    "id": <group id>,
                    "display": <display name>,
                    "members":[
                        {
                            "identifier": <identifier>,
                            "jwtSubject": <jwtSubject>,
                            "display": <display name>
                        }
                    ]
                }
            ]
        Containing the loaded groups information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_post(
            MgmtV1.groupLoadAllForMemberPath,
            {
                "tenantId": tenant_id,
                "identifiers": identifiers,
                "jwtSubjects": jwt_subjects,
            },
            pswd=self._auth.management_key,
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
                            "identifier": <identifier>,
                            "jwtSubject": <jwtSubject>,
                            "display": <display name>
                        }
                    ]
                }
            ]
        Containing the loaded groups information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_post(
            MgmtV1.groupLoadAllGroupMembersPath,
            {
                "tenantId": tenant_id,
                "groupId": group_id,
            },
            pswd=self._auth.management_key,
        )
        return response.json()
