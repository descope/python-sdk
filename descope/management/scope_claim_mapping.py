from __future__ import annotations

from typing import List

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class ScopeClaimMapping(HTTPBase):
    def get(self) -> dict:
        """
        Get the scope claim mappings for the project.

        Return value (dict):
        Return dict in the format {"mappings": [...]}
        "mappings" contains a list of scope claim mapping entries.
        Each entry has: scope (str), claims (dict), description (str).

        Raise:
        AuthException: raised if get operation fails
        """
        response = self._http.post(
            MgmtV1.scope_claim_mapping_get_path,
            body={},
        )
        return response.json()

    def set(
        self,
        mappings: List[dict],
    ):
        """
        Set the scope claim mappings for the project.
        This will replace all existing mappings.

        Args:
        mappings (List[dict]): List of scope claim mapping entries.
                               Each entry should have: scope (str), claims (dict), description (str).

        Raise:
        AuthException: raised if set operation fails
        """
        self._http.post(
            MgmtV1.scope_claim_mapping_set_path,
            body={"mappings": mappings},
        )

    def delete(self):
        """
        Delete all scope claim mappings for the project.
        IMPORTANT: This action is irreversible. Use carefully.

        Raise:
        AuthException: raised if delete operation fails
        """
        self._http.post(
            MgmtV1.scope_claim_mapping_delete_path,
            body={},
        )
