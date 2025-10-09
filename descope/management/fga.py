from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class FGA(HTTPBase):

    def __init__(self, http_client, fga_cache_url: Optional[str] = None):
        super().__init__(http_client)
        self._fga_cache_url = fga_cache_url

    def save_schema(self, schema: str):
        """
        Create or update an FGA schema.
        Args:
        schema (str): the schema in the AuthZ 1.0 DSL
            model AuthZ 1.0

            type user

            type org
            relation member: user
            relation parent: org

            type folder
            relation parent: folder
            relation owner: user | org#member
            relation editor: user
            relation viewer: user

            permission can_create: owner | parent.owner
            permission can_edit: editor | can_create
            permission can_view: viewer | can_edit

            type doc
            relation parent: folder
            relation owner: user | org#member
            relation editor: user
            relation viewer: user

            permission can_create: owner | parent.owner
            permission can_edit: editor | can_create
            permission can_view: viewer | can_edit
        Raise:
        AuthException: raised if saving fails
        """
        self._http.post(
            MgmtV1.fga_save_schema,
            body={"dsl": schema},
            base_url=self._fga_cache_url,
        )

    def create_relations(
        self,
        relations: List[dict],
    ):
        """
        Create the given relations based on the existing schema
        Args:
        relations (List[dict]): the relations to create. Each in the following format:
            {
                "resource": "id of the resource that has the relation",
                "resourceType": "the type of the resource (namespace)",
                "relation": "the relation definition for the relation",
                "target": "the target that has the relation - usually users or other resources",
                "targetType": "the type of the target (namespace) - can also be group#member for target sets"
            }
        Raise:
        AuthException: raised if create relations fails
        """
        self._http.post(
            MgmtV1.fga_create_relations,
            body={"tuples": relations},
            base_url=self._fga_cache_url,
        )

    def delete_relations(
        self,
        relations: List[dict],
    ):
        """
        Delete the given relations based on the existing schema
        Args:
        relations (List[dict]): the relations to create. Each in the format as specified above for (create_relations)
        Raise:
        AuthException: raised if delete relations fails
        """
        self._http.post(
            MgmtV1.fga_delete_relations,
            body={"tuples": relations},
            base_url=self._fga_cache_url,
        )

    def check(
        self,
        relations: List[dict],
    ) -> List[dict]:
        """
        Queries the given relations to see if they exist returning true if they do
        Args:
        relations (List[dict]): List of relation queries each in the format of:
            {
                "resource": "id of the resource that has the relation",
                "resourceType": "the type of the resource (namespace)",
                "relation": "the relation definition for the relation",
                "target": "the target that has the relation - usually users or other resources",
                "targetType": "the type of the target (namespace)"
            }

        Return value (List[dict]):
        Return List in the format
             [
                {
                    "allowed": True|False
                    "relation": {
                        "resource": "id of the resource that has the relation",
                        "resourceType": "the type of the resource (namespace)",
                        "relation": "the relation definition for the relation",
                        "target": "the target that has the relation - usually users or other resources",
                        "targetType": "the type of the target (namespace)"
                    }
                }
            ]
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.fga_check,
            body={"tuples": relations},
            base_url=self._fga_cache_url,
        )
        return list(
            map(
                lambda tuple: {"relation": tuple["tuple"], "allowed": tuple["allowed"]},
                response.json()["tuples"],
            )
        )

    def load_resources_details(self, resource_identifiers: List[dict]) -> List[dict]:
        """
        Load details for the given resource identifiers.
        Args:
            resource_identifiers (List[dict]): list of dicts each containing 'resourceId' and 'resourceType'.
        Returns:
            List[dict]: list of resources details as returned by the server.
        """
        response = self._http.post(
            MgmtV1.fga_resources_load,
            body={"resourceIdentifiers": resource_identifiers},
        )
        return response.json().get("resourcesDetails", [])

    def save_resources_details(self, resources_details: List[dict]) -> None:
        """
        Save details for the given resources.
        Args:
            resources_details (List[dict]): list of dicts each containing 'resourceId' and 'resourceType' plus optionally containing metadata fields such as 'displayName'.
        """
        self._http.post(
            MgmtV1.fga_resources_save,
            body={"resourcesDetails": resources_details},
        )
