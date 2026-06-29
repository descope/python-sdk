from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management._access_key_base import AccessKeyBase
from descope.management.common import (
    AssociatedTenant,
    MgmtV1,
)


class AccessKey(AccessKeyBase, HTTPBase):
    def create(
        self,
        name: str,
        expire_time: int = 0,
        role_names: Optional[List[str]] = None,
        key_tenants: Optional[List[AssociatedTenant]] = None,
        user_id: Optional[str] = None,
        custom_claims: Optional[dict] = None,
        description: Optional[str] = None,
        permitted_ips: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
    ) -> dict:
        """
        Create a new access key.

        Args:
        name (str): Access key name.
        expire_time (int): Access key expiration. Leave at 0 to make it indefinite.
        role_names (List[str]): An optional list of the access key's roles without tenant association. These roles are
            mutually exclusive with the `key_tenant` roles, which take precedence over them.
        key_tenants (List[AssociatedTenant]): An optional list of the access key's tenants, and optionally, their roles per tenant. These roles are
            mutually exclusive with the general `role_names`, and take precedence over them.
        user_id (str): Bind access key to this user id
            If user_id is supplied, then authorizations will be ignored, and the access key will be bound to the user's authorization.
        custom_claims (dict): Optional, map of claims and their values that will be present in the JWT.
        description (str): an optional text the access key can hold.
        permitted_ips: (List[str]): An optional list of IP addresses or CIDR ranges that are allowed to use the access key.
        custom_attributes (dict): Optional, map of custom attributes and their values that will be associated with the access key.

        Return value (dict):
        Return dict in the format
            {
                "key": {},
                "cleartext": {}
            }
        Containing the created access key information and its cleartext. The key cleartext will only be returned on creation.
        Make sure to save it securely.

        Raise:
        AuthException: raised if create operation fails
        """
        role_names = [] if role_names is None else role_names
        key_tenants = [] if key_tenants is None else key_tenants

        response = self._http.post(
            MgmtV1.access_key_create_path,
            body=AccessKey._compose_create_body(
                name,
                expire_time,
                role_names,
                key_tenants,
                user_id,
                custom_claims,
                description,
                permitted_ips,
                custom_attributes,
            ),
        )
        return response.json()

    def load(
        self,
        id: str,
    ) -> dict:
        """
        Load an existing access key.

        Args:
        id (str): The id of the access key to be loaded.

        Return value (dict):
        Return dict in the format
             {"key": {}}
        Containing the loaded access key information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(
            uri=MgmtV1.access_key_load_path,
            params={"id": id},
        )
        return response.json()

    def search_all_access_keys(
        self,
        tenant_ids: Optional[List[str]] = None,
        bound_user_id: Optional[str] = None,
        creating_user: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
    ) -> dict:
        """
        Search all access keys.

        Args:
        tenant_ids (List[str]): Optional list of tenant IDs to filter by
        bound_user_id (str): Optional user ID of bounded user to filter by
        creating_user (str): Optional user name of the creator to filter by
        custom_attributes (dict): Optional dictionary of custom attributes to filter by

        Return value (dict):
        Return dict in the format
             {"keys": []}
        "keys" contains a list of all of the found users and their information

        Raise:
        AuthException: raised if search operation fails
        """
        tenant_ids = [] if tenant_ids is None else tenant_ids

        response = self._http.post(
            MgmtV1.access_keys_search_path,
            body={
                "tenantIds": tenant_ids,
                "boundUserId": bound_user_id,
                "creatingUser": creating_user,
                "customAttributes": custom_attributes,
            },
        )
        return response.json()

    def update(
        self,
        id: str,
        name: str,
        description: Optional[str] = None,
        custom_claims: Optional[dict] = None,
        permitted_ips: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
    ):
        """
        Update an existing access key with the given various fields. IMPORTANT: id and name are mandatory fields.

        Args:
        id (str): The id of the access key to update.
        name (str): The updated access key name.
        description (str): The description of the access key to update. If not provided, it will not be overriden.
        custom_claims (dict): Optional dictionary of custom claims to update. If not provided, it will not be overridden.
        permitted_ips (List[str]): Optional list of permitted IPs to update. If not provided, it will not be overridden.
        custom_attributes (dict): Optional dictionary of custom attributes to update. If not provided, it will not be overridden.

        Raise:
        AuthException: raised if update operation fails
        """
        body: dict[str, str | List[str] | dict] = {
            "id": id,
            "name": name,
        }
        if description is not None:
            body["description"] = description
        if custom_claims is not None:
            body["customClaims"] = custom_claims
        if permitted_ips is not None:
            body["permittedIps"] = permitted_ips
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        self._http.post(
            MgmtV1.access_key_update_path,
            body=body,
        )

    def deactivate(
        self,
        id: str,
    ):
        """
        Deactivate an existing access key. IMPORTANT: This deactivated key will not be usable from this stage.
        It will, however, persist, and can be activated again if needed.

        Args:
        id (str): The id of the access key to be deactivated.

        Raise:
        AuthException: raised if deactivation operation fails
        """
        self._http.post(
            MgmtV1.access_key_deactivate_path,
            body={"id": id},
        )

    def activate(
        self,
        id: str,
    ):
        """
        Activate an existing access key. IMPORTANT: Only deactivated keys can be activated again,
        and become usable once more. New access keys are active by default.

        Args:
        id (str): The id of the access key to be activate.

        Raise:
        AuthException: raised if activation operation fails
        """
        self._http.post(
            MgmtV1.access_key_activate_path,
            body={"id": id},
        )

    def delete(
        self,
        id: str,
    ):
        """
        Delete an existing access key. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The id of the access key to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.access_key_delete_path,
            body={"id": id},
        )

    def rotate(
        self,
        id: str,
    ) -> dict:
        """
        Rotate an existing access key. Regenerates the secret while preserving the same access key ID,
        name, roles, tenants, expiry, and metadata.

        Args:
        id (str): The id of the access key to be rotated.

        Return value (dict):
        Return dict in the format
            {
                "key": {},
                "cleartext": {}
            }
        The cleartext is the new secret and is only visible once. Save it immediately.
        The previous secret stops working as soon as this call returns.

        Raise:
        AuthException: raised if rotation operation fails
        """
        response = self._http.post(
            MgmtV1.access_key_rotate_path,
            body={"id": id},
        )
        return response.json()

    def activate_batch(
        self,
        ids: List[str],
    ):
        """
        Activate multiple existing access keys in a single request.

        Args:
        ids (List[str]): The list of access key IDs to be activated.

        Raise:
        AuthException: raised if batch activation operation fails
        """
        self._http.post(
            MgmtV1.access_key_activate_batch_path,
            body={"ids": ids},
        )

    def deactivate_batch(
        self,
        ids: List[str],
    ):
        """
        Deactivate multiple existing access keys in a single request.

        Args:
        ids (List[str]): The list of access key IDs to be deactivated.

        Raise:
        AuthException: raised if batch deactivation operation fails
        """
        self._http.post(
            MgmtV1.access_key_deactivate_batch_path,
            body={"ids": ids},
        )

    def delete_batch(
        self,
        ids: List[str],
    ):
        """
        Delete multiple existing access keys in a single request. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        ids (List[str]): The list of access key IDs to be deleted.

        Raise:
        AuthException: raised if batch deletion operation fails
        """
        self._http.post(
            MgmtV1.access_key_delete_batch_path,
            body={"ids": ids},
        )
