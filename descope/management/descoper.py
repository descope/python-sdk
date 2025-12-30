from typing import List, Optional, Any

from descope._http_base import HTTPBase
from descope.management.common import (
    DescoperAttributes,
    DescoperCreate,
    DescoperRBAC,
    MgmtV1,
    descopers_to_dict,
)


class Descoper(HTTPBase):
    def create(
        self,
        descopers: List[DescoperCreate],
    ) -> dict:
        """
        Create new Descopers.

        Args:
        descopers (List[DescoperCreate]): List of Descopers to create.
            Note that tags are referred to by name, without the company ID prefix.

        Return value (dict):
        Return dict in the format
            {
                "descopers": [...],
                "total": <int>
            }

        Raise:
        AuthException: raised if create operation fails
        """
        if not descopers:
            raise ValueError("descopers list cannot be empty")

        response = self._http.put(
            MgmtV1.descoper_create_path,
            body={"descopers": descopers_to_dict(descopers)},
        )
        return response.json()

    def update(
        self,
        id: str,
        attributes: Optional[DescoperAttributes] = None,
        rbac: Optional[DescoperRBAC] = None,
    ) -> dict:
        """
        Update an existing Descoper's RBAC and/or Attributes.

        IMPORTANT: All parameter *fields*, if set, will override whatever values are currently set
        in the existing Descoper. Use carefully.

        Args:
        id (str): The id of the Descoper to update.
        attributes (DescoperAttributes): Optional attributes to update.
        rbac (DescoperRBAC): Optional RBAC configuration to update.

        Return value (dict):
        Return dict in the format
             {"descoper": {...}}
        Containing the updated Descoper information.

        Raise:
        AuthException: raised if update operation fails
        """
        if not id:
            raise ValueError("id cannot be empty")

        body: dict[str, Any] = {"id": id}
        if attributes is not None:
            body["attributes"] = attributes.to_dict()
        if rbac is not None:
            body["rbac"] = rbac.to_dict()

        response = self._http.patch(
            MgmtV1.descoper_update_path,
            body=body,
        )
        return response.json()

    def load(
        self,
        id: str,
    ) -> dict:
        """
        Load an existing Descoper by ID.

        Args:
        id (str): The id of the Descoper to load.

        Return value (dict):
        Return dict in the format
             {"descoper": {...}}
        Containing the loaded Descoper information.

        Raise:
        AuthException: raised if load operation fails
        """
        if not id:
            raise ValueError("id cannot be empty")

        response = self._http.get(
            uri=MgmtV1.descoper_load_path,
            params={"id": id},
        )
        return response.json()

    def delete(
        self,
        id: str,
    ):
        """
        Delete an existing Descoper. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The id of the Descoper to delete.

        Raise:
        AuthException: raised if delete operation fails
        """
        if not id:
            raise ValueError("id cannot be empty")

        self._http.delete(
            uri=MgmtV1.descoper_delete_path,
            params={"id": id},
        )

    def list(
        self,
    ) -> dict:
        """
        List all Descopers.

        Return value (dict):
        Return dict in the format
            {
                "descopers": [...],
                "total": <int>
            }
        Containing all Descopers and the total count.

        Raise:
        AuthException: raised if list operation fails
        """
        response = self._http.post(
            MgmtV1.descoper_list_path,
            body={},
        )
        return response.json()
