from typing import Any, List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1, tenantSettings


class Tenant(HTTPBase):
    def create(
        self,
        name: str,
        id: Optional[str] = None,
        self_provisioning_domains: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
        enforce_sso: Optional[bool] = False,
        disabled: Optional[bool] = False,
    ) -> dict:
        """
        Create a new tenant with the given name. Tenant IDs are provisioned automatically, but can be provided
        explicitly if needed. Both the name and ID must be unique per project.

        Args:
        name (str): The tenant's name
        id (str): Optional tenant ID.
        self_provisioning_domains (List[str]): An optional list of domain that are associated with this tenant.
            Users authenticating from these domains will be associated with this tenant.
        custom_attributes (dict): Optional, set the different custom attributes values of the keys that were previously configured in Descope console app
        enforce_sso (bool): Optional, login to the tenant is possible only using the configured sso
        disabled (bool): Optional, login to the tenant will be disabled

        Return value (dict):
        Return dict in the format
             {"id": <id>}

        Raise:
        AuthException: raised if creation operation fails
        """
        self_provisioning_domains = (
            [] if self_provisioning_domains is None else self_provisioning_domains
        )

        response = self._http.post(
            MgmtV1.tenant_create_path,
            body=Tenant._compose_create_update_body(
                name,
                id,
                self_provisioning_domains,
                custom_attributes,
                enforce_sso,
                disabled,
            ),
        )
        return response.json()

    def update(
        self,
        id: str,
        name: str,
        self_provisioning_domains: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
        enforce_sso: Optional[bool] = False,
        disabled: Optional[bool] = False,
    ):
        """
        Update an existing tenant with the given name and domains. IMPORTANT: All parameters are used as overrides
        to the existing tenant. Empty fields will override populated fields. Use carefully.

        Args:
        id (str): The ID of the tenant to update.
        name (str): Updated tenant name
        self_provisioning_domains (List[str]): An optional list of domain that are associated with this tenant.
            Users authenticating from these domains will be associated with this tenant.
        custom_attributes (dict): Optional, set the different custom attributes values of the keys that were previously configured in Descope console app
        enforce_sso (bool): Optional, login to the tenant is possible only using the configured sso
        disabled (bool): Optional, login to the tenant will be disabled

        Raise:
        AuthException: raised if creation operation fails
        """
        self_provisioning_domains = (
            [] if self_provisioning_domains is None else self_provisioning_domains
        )

        self._http.post(
            MgmtV1.tenant_update_path,
            body=Tenant._compose_create_update_body(
                name,
                id,
                self_provisioning_domains,
                custom_attributes,
                enforce_sso,
                disabled,
            ),
        )

    def update_settings(
        self,
        id: str,
        tenant_settings: tenantSettings
    ):
        """
        Update an existing tenant's session settings.

        Args:
        id (str): The ID of the tenant to update.
        session_settings (dict): The session settings to set for the tenant.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.tenant_settings_path,
            params={"id": id},
            body= tenant_settings,
        )

    def delete(
        self,
        id: str,
        cascade: bool = False,
    ):
        """
        Delete an existing tenant. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The ID of the tenant that's to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.tenant_delete_path,
            body={"id": id, "cascade": cascade},
        )

    def load(
        self,
        id: str,
    ) -> dict:
        """
        Load tenant by id.

        Args:
        id (str): The ID of the tenant to load.

        Return value (dict):
        Return dict in the format
             {"id": <id>, "name": <name>, "selfProvisioningDomains": [], "customAttributes: {}, "createdTime": <timestamp>}
        Containing the loaded tenant information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(
            MgmtV1.tenant_load_path,
            params={"id": id},
        )
        return response.json()
    
    def load_settings(
        self,
        id: str,
    ) -> dict:
        """
        Load tenant session settings by id.

        Args:
        id (str): The ID of the tenant to load session settings for.

        Return value (dict):
        Return dict in the format
            { "domains":<list[str]>, "selfProvisioningDomains":<list[str]>, "authType":<str>,
             "enabled":<bool>, "refreshTokenExpiration":<int>, "refreshTokenExpirationUnit":<str>,
             "sessionTokenExpiration":<int>, "sessionTokenExpirationUnit":<str>,
             "stepupTokenExpiration":<int>, "stepupTokenExpirationUnit":<str>,
             "enableInactivity":<bool>, "inactivityTime":<int>, "inactivityTimeUnit":<str>,
             "JITDisabled":<bool> }
        Containing the loaded tenant session settings.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(
            MgmtV1.tenant_settings_path,
            params={"id": id},
        )
        return response.json()

    def load_all(
        self,
    ) -> dict:
        """
        Load all tenants.

        Return value (dict):
        Return dict in the format
             {"tenants": [{"id": <id>, "name": <name>, "selfProvisioningDomains": [], customAttributes: {}, "createdTime": <timestamp>}]}
        Containing the loaded tenant information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(
            MgmtV1.tenant_load_all_path,
        )
        return response.json()

    def search_all(
        self,
        ids: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
        self_provisioning_domains: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
    ) -> dict:
        """
        Search all tenants.

        Args:
        ids (List[str]): Optional list of tenant IDs to filter by
        names (List[str]): Optional list of names to filter by
        self_provisioning_domains (List[str]): Optional list of self provisioning domains to filter by
        custom_attributes (dict): Optional search for a attribute with a given value

        Return value (dict):
        Return dict in the format
             {"tenants": [{"id": <id>, "name": <name>, "selfProvisioningDomains": [], customAttributes:{}}]}
        Containing the loaded tenant information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.post(
            MgmtV1.tenant_search_all_path,
            body={
                "tenantIds": ids,
                "tenantNames": names,
                "tenantSelfProvisioningDomains": self_provisioning_domains,
                "customAttributes": custom_attributes,
            },
        )
        return response.json()

    @staticmethod
    def _compose_create_update_body(
        name: str,
        id: Optional[str],
        self_provisioning_domains: List[str],
        custom_attributes: Optional[dict] = None,
        enforce_sso: Optional[bool] = False,
        disabled: Optional[bool] = False,
    ) -> dict:
        body: dict[str, Any] = {
            "name": name,
            "id": id,
            "selfProvisioningDomains": self_provisioning_domains,
            "enforceSSO": enforce_sso,
            "disabled": disabled,
        }
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        return body
