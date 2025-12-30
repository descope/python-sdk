from typing import List, Optional, Any

from descope._http_base import HTTPBase
from descope.management.common import (
    MgmtKeyReBac,
    MgmtKeyStatus,
    MgmtV1,
)


class ManagementKey(HTTPBase):
    def create(
        self,
        name: str,
        rebac: MgmtKeyReBac,
        description: Optional[str] = None,
        expires_in: int = 0,
        permitted_ips: Optional[List[str]] = None,
    ) -> dict:
        """
        Create a new management key.

        Args:
        name (str): The name of the management key.
        rebac (MgmtKeyReBac): RBAC configuration for the key.
        description (str): Optional description for the management key.
        expires_in (int): Expiration time in seconds (0 for no expiration).
        permitted_ips (List[str]): Optional list of IP addresses or CIDR ranges that are allowed to use this key.

        Return value (dict):
        Return dict in the format
            {
                "key": {...},
                "cleartext": "..."
            }

        Raise:
        AuthException: raised if create operation fails
        """
        if not name:
            raise ValueError("name cannot be empty")
        if rebac is None:
            raise ValueError("rebac cannot be empty")

        body: dict[str, Any] = {
            "name": name,
            "description": description,
            "expiresIn": expires_in,
            "permittedIps": permitted_ips if permitted_ips is not None else [],
            "reBac": rebac.to_dict(),
        }

        response = self._http.put(
            MgmtV1.mgmt_key_create_path,
            body=body,
        )
        return response.json()

    def update(
        self,
        id: str,
        name: str,
        description: str,
        permitted_ips: List[str],
        status: MgmtKeyStatus,
    ) -> dict:
        """
        Update an existing management key.

        IMPORTANT: All parameters will override whatever values are currently set
        in the existing management key. Use carefully.

        Args:
        id (str): The id of the management key to update.
        name (str): The updated name.
        description (str): Updated description.
        permitted_ips (List[str]): Updated list of IP addresses or CIDR ranges.
        status (MgmtKeyStatus): Updated status.

        Return value (dict):
        Return dict in the format
             {"key": {...}}
        Containing the updated management key information.

        Raise:
        AuthException: raised if update operation fails
        """
        if not id:
            raise ValueError("id cannot be empty")
        if not name:
            raise ValueError("name cannot be empty")
        if status is None:
            raise ValueError("status cannot be empty")

        body: dict[str, Any] = {
            "id": id,
            "name": name,
            "description": description,
            "permittedIps": permitted_ips if permitted_ips is not None else [],
            "status": status.value,
        }

        response = self._http.patch(
            MgmtV1.mgmt_key_update_path,
            body=body,
        )
        return response.json()

    def load(
        self,
        id: str,
    ) -> dict:
        """
        Get a management key by ID.

        Args:
        id (str): The id of the management key to load.

        Return value (dict):
        Return dict in the format
             {"key": {...}}
        Containing the loaded management key information.

        Raise:
        AuthException: raised if load operation fails
        """
        if not id:
            raise ValueError("id cannot be empty")

        response = self._http.get(
            uri=MgmtV1.mgmt_key_load_path,
            params={"id": id},
        )
        return response.json()

    def delete(
        self,
        ids: List[str],
    ) -> dict:
        """
        Delete existing management keys. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        ids (List[str]): The ids of the management keys to delete.

        Return value (dict):
        Return dict in the format
            {"total": <int>}
        Containing the number of keys deleted.

        Raise:
        AuthException: raised if delete operation fails
        """
        if not ids:
            raise ValueError("ids list cannot be empty")

        response = self._http.post(
            uri=MgmtV1.mgmt_key_delete_path,
            body={"ids": ids},
        )
        return response.json()

    def search(self) -> dict:
        """
        Search for management keys.

        Return value (dict):
        Return dict in the format
            {
                "keys": [...]
            }
        Containing the found management keys.

        Raise:
        AuthException: raised if search operation fails
        """
        response = self._http.get(
            MgmtV1.mgmt_key_search_path,
        )
        return response.json()
