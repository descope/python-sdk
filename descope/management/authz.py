from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class Authz(HTTPBase):
    def save_schema(self, schema: dict, upgrade: bool = False):
        """
        Create or update the ReBAC schema.
        In case of update, will update only given namespaces and will not delete namespaces unless upgrade flag is true.
        Args:
        schema (dict): the schema dict with format
            {
                "name": "name-of-schema",
                "namespaces": [
                    {
                        "name": "name-of-namespace",
                        "relationDefinitions": [
                            {
                                "name": "name-of-relation-definition",
                                "complexDefinition": {
                                    "nType": "one of child|union|intersect|sub",
                                    "children": "optional list of node children - same format as complexDefinition",
                                    "expression": {
                                        "neType": "one of self|targetSet|relationLeft|relationRight",
                                        "relationDefinition": "name of relation definition for relationLeft and relationRight",
                                        "relationDefinitionNamespace": "the namespace for the rd above",
                                        "targetRelationDefinition": "relation definition for targetSet and relationLeft/right",
                                        "targetRelationDefinitionNamespace": "the namespace for above"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        Schema name can be used for projects to track versioning.
        Raise:
        AuthException: raised if saving fails
        """
        self._http.post(
            MgmtV1.authz_schema_save,
            body={"schema": schema, "upgrade": upgrade},
        )

    def delete_schema(self):
        """
        Delete the schema for the project which will also delete all relations.
        Raise:
        AuthException: raised if delete schema fails
        """
        self._http.post(
            MgmtV1.authz_schema_delete,
        )

    def load_schema(self) -> dict:
        """
        Load the schema for the project
        Return value (dict):
        Return dict in the format of schema as above (see save_schema)
        Raise:
        AuthException: raised if load schema fails
        """
        response = self._http.post(
            MgmtV1.authz_schema_load,
        )
        return response.json()["schema"]

    def save_namespace(
        self, namespace: dict, old_name: str = "", schema_name: str = ""
    ):
        """
        Create or update the given namespace
        Will not delete relation definitions not mentioned in the namespace.
        Args:
        namespace (dict): namespace in the format as specified above (see save_schema)
        old_name (str): is used if we are changing the namespace name
        schema_name (str): is optional and can be used to track the current schema version.
        Raise:
        AuthException: raised if save namespace fails
        """
        body: dict[str, Any] = {"namespace": namespace}
        if old_name != "":
            body["oldName"] = old_name
        if schema_name != "":
            body["schemaName"] = schema_name
        self._http.post(
            MgmtV1.authz_ns_save,
            body=body,
        )

    def delete_namespace(self, name: str, schema_name: str = ""):
        """
        delete_namespace will also delete the relevant relations.
        Args:
        name (str): namespace name to delete
        schema_name (str): is optional and can be used to track the current schema version.
        Raise:
        AuthException: raised if delete namespace fails
        """
        body: dict[str, Any] = {"name": name}
        if schema_name != "":
            body["schemaName"] = schema_name
        self._http.post(
            MgmtV1.authz_ns_delete,
            body=body,
        )

    def save_relation_definition(
        self,
        relation_definition: dict,
        namespace: str,
        old_name: str = "",
        schema_name: str = "",
    ):
        """
        Create or update the given relation definition
        Will not delete relation definitions not mentioned in the namespace.
        Args:
        relation_definition (dict): relation definition in the format as specified above (see save_schema)
        namespace (str): the namespace for the relation definition
        old_name (str): is used if we are changing the relation definition name
        schema_name (str): is optional and can be used to track the current schema version.
        Raise:
        AuthException: raised if save relation definition fails
        """
        body: dict[str, Any] = {
            "relationDefinition": relation_definition,
            "namespace": namespace,
        }
        if old_name != "":
            body["oldName"] = old_name
        if schema_name != "":
            body["schemaName"] = schema_name
        self._http.post(
            MgmtV1.authz_rd_save,
            body=body,
        )

    def delete_relation_definition(
        self, name: str, namespace: str, schema_name: str = ""
    ):
        """
        delete_relation_definition will also delete the relevant relations.
        Args:
        name (str): relation definition name to delete
        namespace (str): the namespace for the relation definition
        schema_name (str): is optional and can be used to track the current schema version.
        Raise:
        AuthException: raised if delete namespace fails
        """
        body: dict[str, Any] = {"name": name, "namespace": namespace}
        if schema_name != "":
            body["schemaName"] = schema_name
        self._http.post(
            MgmtV1.authz_rd_delete,
            body=body,
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
                "relationDefinition": "the relation definition for the relation",
                "namespace": "namespace for the relation definition",
                "target": "the target that has the relation - usually users or other resources",
                "targetSetResource": "if the target is a group that has another relation",
                "targetSetRelationDefinition": "the relation definition for the targetSet group",
                "targetSetRelationDefinitionNamespace": "the namespace for the relation definition for the targetSet group",
                "query": {
                    "tenants": ["t1", "t2"],
                    "roles": ["r1", "r2"],
                    "text": "full-text-search",
                    "statuses": ["enabled|disabled|invited"],
                    "ssoOnly": True|False,
                    "withTestUser": True|False,
                    "customAttributes": {
                        "key": "value",
                        ...
                    }
                }
            }
            Each relation should have exactly one of: target, targetSet, query
            Regarding query above, it should be specified if the target is a set of users that matches the query - all fields are optional
        Raise:
        AuthException: raised if create relations fails
        """
        self._http.post(
            MgmtV1.authz_re_create,
            body={"relations": relations},
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
            MgmtV1.authz_re_delete,
            body={"relations": relations},
        )

    def delete_relations_for_resources(
        self,
        resources: List[str],
    ):
        """
        Delete all relations to the given resources
        Args:
        resources (List[str]): the list of resources to delete any relations for
        Raise:
        AuthException: raised if delete relations for resources fails
        """
        self._http.post(
            MgmtV1.authz_re_delete_resources,
            body={"resources": resources},
        )

    def has_relations(
        self,
        relation_queries: List[dict],
    ) -> List[dict]:
        """
        Queries the given relations to see if they exist returning true if they do
        Args:
        relation_queries (List[dict]): List of queries each in the format of:
            {
                "resource": "resource for the relation query",
                "relationDefinition": "the relation definition for the relation query",
                "namespace": "namespace for the relation definition",
                "target": "the target that has the relation - usually users or other resources"
            }

        Return value (List[dict]):
        Return List in the format
             [
                {
                    "resource": "resource for the relation query",
                    "relationDefinition": "the relation definition for the relation query",
                    "namespace": "namespace for the relation definition",
                    "target": "the target that has the relation - usually users or other resources",
                    "hasRelation": True|False
                }
            ]
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.authz_re_has_relations,
            body={"relationQueries": relation_queries},
        )
        return response.json()["relationQueries"]

    def who_can_access(
        self, resource: str, relation_definition: str, namespace: str
    ) -> List[dict]:
        """
        Finds the list of targets (usually users) who can access the given resource with the given RD
        Args:
        resource (str): the resource we are checking
        relation_definition (str): the RD we are checking
        namespace (str): the namespace for the RD

        Return value (List[str]): list of targets (user IDs usually that have the access)
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.authz_re_who,
            body={
                "resource": resource,
                "relationDefinition": relation_definition,
                "namespace": namespace,
            },
        )
        return response.json()["targets"]

    def resource_relations(self, resource: str) -> List[dict]:
        """
        Returns the list of all defined relations (not recursive) on the given resource.
        Args:
        resource (str): the resource we are listing relations for

        Return value (List[dict]):
        Return List of relations each in the format of a relation as documented in create_relations
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.authz_re_resource,
            body={"resource": resource},
        )
        return response.json()["relations"]

    def targets_relations(self, targets: List[str]) -> List[dict]:
        """
        Returns the list of all defined relations (not recursive) for the given targets.
        Args:
        targets (List[str]): the list of targets we are returning the relations for

        Return value (List[dict]):
        Return List of relations each in the format of a relation as documented in create_relations
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.authz_re_targets,
            body={"targets": targets},
        )
        return response.json()["relations"]

    def what_can_target_access(self, target: str) -> List[dict]:
        """
        Returns the list of all relations for the given target including derived relations from the schema tree.
        Args:
        target (str): the target we are returning the relations for

        Return value (List[dict]):
        Return List of relations each in the format of a relation as documented in create_relations
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.authz_re_target_all,
            body={"target": target},
        )
        return response.json()["relations"]

    def what_can_target_access_with_relation(
        self, target: str, relation_definition: str, namespace: str
    ) -> List[dict]:
        """
        Returns the list of all resources that the target has the given relation to including all derived relations
        Args:
        target (str): the target we are returning the relations for
        relation_definition (str): the RD we are checking
        namespace (str): the namespace for the RD

        Return value (List[dict]):
        Return List of relations each in the format of a relation as documented in create_relations
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.authz_re_target_with_relation,
            body={
                "target": target,
                "relationDefinition": relation_definition,
                "namespace": namespace,
            },
        )
        return response.json()["relations"]

    def get_modified(self, since: Optional[datetime] = None) -> dict:
        """
        Get all targets and resources changed since the given date.
        Args:
        since (datetime): only return changes from this given datetime

        Return value (dict):
        Dict including "resources" list of strings, "targets" list of strings and "schemaChanged" bool
        Raise:
        AuthException: raised if query fails
        """
        response = self._http.post(
            MgmtV1.authz_get_modified,
            body={
                "since": (
                    int(since.replace(tzinfo=timezone.utc).timestamp() * 1000)
                    if since
                    else 0
                )
            },
        )
        return response.json()["relations"]
