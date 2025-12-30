from enum import Enum
from typing import Dict, List, Optional, Any


class SessionExpirationUnit(Enum):
    MINUTES = "minutes"
    HOURS = "hours"
    DAYS = "days"
    WEEKS = "weeks"


class TenantAuthType(Enum):
    NONE = "none"
    SAML = "saml"
    OIDC = "oidc"


class SSOSetupSuiteSettingsDisabledFeatures:
    def __init__(
        self,
        saml: bool = False,
        oidc: bool = False,
        scim: bool = False,
        sso_domains: bool = False,
        group_mapping: bool = False,
    ):
        self.saml = saml
        self.oidc = oidc
        self.scim = scim
        self.sso_domains = sso_domains
        self.group_mapping = group_mapping

    def to_dict(self) -> Dict[str, bool]:
        return {
            "saml": self.saml,
            "oidc": self.oidc,
            "scim": self.scim,
            "ssoDomains": self.sso_domains,
            "groupMapping": self.group_mapping,
        }


class SSOSetupSuiteSettings:
    def __init__(
        self,
        enabled: bool,
        style_id: Optional[str] = None,
        disabled_features: Optional[SSOSetupSuiteSettingsDisabledFeatures] = None,
    ):
        self.enabled = enabled
        self.style_id = style_id
        self.disabled_features = disabled_features

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"enabled": self.enabled}
        if self.style_id is not None:
            result["styleId"] = self.style_id
        if self.disabled_features is not None:
            result["disabledFeatures"] = self.disabled_features.to_dict()
        return result


class AccessType(Enum):
    OFFLINE = "offline"
    ONLINE = "online"


class PromptType(Enum):
    NONE = "none"
    LOGIN = "login"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"


class URLParam:
    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value}


def url_params_to_dict(url_params: Optional[List[URLParam]] = None) -> list:
    if url_params is None:
        return []
    return [param.to_dict() for param in url_params]


class MgmtV1:
    # tenant
    tenant_create_path = "/v1/mgmt/tenant/create"
    tenant_update_path = "/v1/mgmt/tenant/update"
    tenant_delete_path = "/v1/mgmt/tenant/delete"
    tenant_load_path = "/v1/mgmt/tenant"
    tenant_settings_path = "/v1/mgmt/tenant/settings"
    tenant_load_all_path = "/v1/mgmt/tenant/all"
    tenant_search_all_path = "/v1/mgmt/tenant/search"

    # sso application
    sso_application_oidc_create_path = "/v1/mgmt/sso/idp/app/oidc/create"
    sso_application_saml_create_path = "/v1/mgmt/sso/idp/app/saml/create"
    sso_application_oidc_update_path = "/v1/mgmt/sso/idp/app/oidc/update"
    sso_application_saml_update_path = "/v1/mgmt/sso/idp/app/saml/update"
    sso_application_delete_path = "/v1/mgmt/sso/idp/app/delete"
    sso_application_load_path = "/v1/mgmt/sso/idp/app/load"
    sso_application_load_all_path = "/v1/mgmt/sso/idp/apps/load"

    # outbound application
    outbound_application_create_path = "/v1/mgmt/outbound/app/create"
    outbound_application_update_path = "/v1/mgmt/outbound/app/update"
    outbound_application_delete_path = "/v1/mgmt/outbound/app/delete"
    outbound_application_load_path = "/v1/mgmt/outbound/app"
    outbound_application_load_all_path = "/v1/mgmt/outbound/apps"
    outbound_application_fetch_token_by_scopes_path = "/v1/mgmt/outbound/app/user/token"
    outbound_application_fetch_token_path = "/v1/mgmt/outbound/app/user/token/latest"
    outbound_application_fetch_tenant_token_by_scopes_path = (
        "/v1/mgmt/outbound/app/tenant/token"
    )
    outbound_application_fetch_tenant_token_path = (
        "/v1/mgmt/outbound/app/tenant/token/latest"
    )

    # user
    user_create_path = "/v1/mgmt/user/create"
    test_user_create_path = "/v1/mgmt/user/create/test"
    user_create_batch_path = "/v1/mgmt/user/create/batch"
    user_update_path = "/v1/mgmt/user/update"
    user_patch_path = "/v1/mgmt/user/patch"
    user_patch_batch_path = "/v1/mgmt/user/patch/batch"
    user_delete_path = "/v1/mgmt/user/delete"
    user_logout_path = "/v1/mgmt/user/logout"
    user_delete_all_test_users_path = "/v1/mgmt/user/test/delete/all"
    user_load_path = "/v1/mgmt/user"
    users_load_path = "/v1/mgmt/users/load"
    users_search_path = "/v2/mgmt/user/search"
    test_users_search_path = "/v2/mgmt/user/search/test"
    user_get_provider_token = "/v1/mgmt/user/provider/token"
    user_update_status_path = "/v1/mgmt/user/update/status"
    user_update_login_id_path = "/v1/mgmt/user/update/loginid"
    user_update_email_path = "/v1/mgmt/user/update/email"
    user_update_phone_path = "/v1/mgmt/user/update/phone"
    user_update_name_path = "/v1/mgmt/user/update/name"
    user_update_picture_path = "/v1/mgmt/user/update/picture"
    user_update_custom_attribute_path = "/v1/mgmt/user/update/customAttribute"
    user_set_role_path = "/v1/mgmt/user/update/role/set"
    user_add_role_path = "/v2/mgmt/user/update/role/add"
    user_remove_role_path = "/v1/mgmt/user/update/role/remove"
    user_add_sso_apps = "/v1/mgmt/user/update/ssoapp/add"
    user_set_sso_apps = "/v1/mgmt/user/update/ssoapp/set"
    user_remove_sso_apps = "/v1/mgmt/user/update/ssoapp/remove"
    user_set_password_path = "/v1/mgmt/user/password/set"  # Deprecated
    user_set_temporary_password_path = "/v1/mgmt/user/password/set/temporary"
    user_set_active_password_path = "/v1/mgmt/user/password/set/active"
    user_expire_password_path = "/v1/mgmt/user/password/expire"
    user_remove_all_passkeys_path = "/v1/mgmt/user/passkeys/delete"
    user_remove_totp_seed_path = "/v1/mgmt/user/totp/delete"
    user_add_tenant_path = "/v1/mgmt/user/update/tenant/add"
    user_remove_tenant_path = "/v1/mgmt/user/update/tenant/remove"
    user_generate_otp_for_test_path = "/v1/mgmt/tests/generate/otp"
    user_generate_magic_link_for_test_path = "/v1/mgmt/tests/generate/magiclink"
    user_generate_enchanted_link_for_test_path = "/v1/mgmt/tests/generate/enchantedlink"
    user_generate_embedded_link_path = "/v1/mgmt/user/signin/embeddedlink"
    user_generate_sign_up_embedded_link_path = "/v1/mgmt/user/signup/embeddedlink"
    user_history_path = "/v1/mgmt/user/history"

    # access key
    access_key_create_path = "/v1/mgmt/accesskey/create"
    access_key_load_path = "/v1/mgmt/accesskey"
    access_keys_search_path = "/v1/mgmt/accesskey/search"
    access_key_update_path = "/v1/mgmt/accesskey/update"
    access_key_deactivate_path = "/v1/mgmt/accesskey/deactivate"
    access_key_activate_path = "/v1/mgmt/accesskey/activate"
    access_key_delete_path = "/v1/mgmt/accesskey/delete"

    # sso
    sso_settings_path = "/v1/mgmt/sso/settings"
    sso_metadata_path = "/v1/mgmt/sso/metadata"
    sso_mapping_path = "/v1/mgmt/sso/mapping"
    sso_load_settings_path = "/v2/mgmt/sso/settings"  # v2 only
    sso_configure_oidc_settings = "/v1/mgmt/sso/oidc"
    sso_configure_saml_settings = "/v1/mgmt/sso/saml"
    sso_configure_saml_by_metadata_settings = "/v1/mgmt/sso/saml/metadata"

    # jwt
    update_jwt_path = "/v1/mgmt/jwt/update"
    impersonate_path = "/v1/mgmt/impersonate"
    stop_impersonation_path = "/v1/mgmt/stop/impersonation"
    mgmt_sign_in_path = "/v1/mgmt/auth/signin"
    mgmt_sign_up_path = "/v1/mgmt/auth/signup"
    mgmt_sign_up_or_in_path = "/v1/mgmt/auth/signup-in"
    anonymous_path = "/v1/mgmt/auth/anonymous"

    # permission
    permission_create_path = "/v1/mgmt/permission/create"
    permission_update_path = "/v1/mgmt/permission/update"
    permission_delete_path = "/v1/mgmt/permission/delete"
    permission_load_all_path = "/v1/mgmt/permission/all"

    # role
    role_create_path = "/v1/mgmt/role/create"
    role_update_path = "/v1/mgmt/role/update"
    role_delete_path = "/v1/mgmt/role/delete"
    role_load_all_path = "/v1/mgmt/role/all"
    role_search_path = "/v1/mgmt/role/search"

    # flow
    flow_list_path = "/v1/mgmt/flow/list"
    flow_delete_path = "/v1/mgmt/flow/delete"
    flow_import_path = "/v1/mgmt/flow/import"
    flow_export_path = "/v1/mgmt/flow/export"
    flow_run_path = "/v1/mgmt/flow/run"
    flow_async_run_path = "/v1/mgmt/flow/async/run"
    flow_async_result_path = "/v1/mgmt/flow/async/result"

    # theme
    theme_import_path = "/v1/mgmt/theme/import"
    theme_export_path = "/v1/mgmt/theme/export"

    # group
    group_load_all_path = "/v1/mgmt/group/all"
    group_load_all_for_member_path = "/v1/mgmt/group/member/all"
    group_load_all_group_members_path = "/v1/mgmt/group/members"

    # Audit
    audit_search = "/v1/mgmt/audit/search"
    audit_create_event = "/v1/mgmt/audit/event"

    # Authz ReBAC
    authz_schema_save = "/v1/mgmt/authz/schema/save"
    authz_schema_delete = "/v1/mgmt/authz/schema/delete"
    authz_schema_load = "/v1/mgmt/authz/schema/load"
    authz_ns_save = "/v1/mgmt/authz/ns/save"
    authz_ns_delete = "/v1/mgmt/authz/ns/delete"
    authz_rd_save = "/v1/mgmt/authz/rd/save"
    authz_rd_delete = "/v1/mgmt/authz/rd/delete"
    authz_re_create = "/v1/mgmt/authz/re/create"
    authz_re_delete = "/v1/mgmt/authz/re/delete"
    authz_re_delete_resources = "/v1/mgmt/authz/re/deleteresources"
    authz_re_has_relations = "/v1/mgmt/authz/re/has"
    authz_re_who = "/v1/mgmt/authz/re/who"
    authz_re_resource = "/v1/mgmt/authz/re/resource"
    authz_re_targets = "/v1/mgmt/authz/re/targets"
    authz_re_target_all = "/v1/mgmt/authz/re/targetall"
    authz_re_target_with_relation = "/v1/mgmt/authz/re/targetwithrelation"
    authz_get_modified = "/v1/mgmt/authz/getmodified"

    # FGA (new style Authz)
    fga_save_schema = "/v1/mgmt/fga/schema"
    fga_create_relations = "/v1/mgmt/fga/relations"
    fga_delete_relations = "/v1/mgmt/fga/relations/delete"
    fga_check = "/v1/mgmt/fga/check"
    fga_resources_load = "/v1/mgmt/fga/resources/load"
    fga_resources_save = "/v1/mgmt/fga/resources/save"

    # Project
    project_update_name = "/v1/mgmt/project/update/name"
    project_update_tags = "/v1/mgmt/project/update/tags"
    project_clone = "/v1/mgmt/project/clone"
    project_export = "/v1/mgmt/project/export"
    project_import = "/v1/mgmt/project/import"
    project_list_projects = "/v1/mgmt/projects/list"

    # Descoper
    descoper_create_path = "/v1/mgmt/descoper"
    descoper_update_path = "/v1/mgmt/descoper"
    descoper_load_path = "/v1/mgmt/descoper"
    descoper_delete_path = "/v1/mgmt/descoper"
    descoper_list_path = "/v1/mgmt/descoper/list"

    # management key
    mgmt_key_create_path = "/v1/mgmt/managementkey"
    mgmt_key_update_path = "/v1/mgmt/managementkey"
    mgmt_key_load_path = "/v1/mgmt/managementkey"
    mgmt_key_delete_path = "/v1/mgmt/managementkey/delete"
    mgmt_key_search_path = "/v1/mgmt/managementkey/search"


class MgmtSignUpOptions:
    def __init__(
        self,
        custom_claims: Optional[dict] = None,
        refresh_duration: Optional[int] = None,
    ):
        self.custom_claims = custom_claims
        self.refresh_duration = refresh_duration


class FlowRunOptions:
    """
    Options for running a flow.
    """

    def __init__(
        self,
        flow_input: Optional[Dict[str, Any]] = None,
        preview: Optional[bool] = None,
        tenant: Optional[str] = None,
    ):
        self.flow_input = flow_input
        self.preview = preview
        self.tenant = tenant

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self.flow_input is not None:
            result["input"] = self.flow_input
        if self.preview is not None:
            result["preview"] = self.preview
        if self.tenant is not None:
            result["tenant"] = self.tenant
        return result

    @staticmethod
    def from_dict(options: Optional[dict]) -> Optional["FlowRunOptions"]:
        if options is None:
            return None
        return FlowRunOptions(
            flow_input=options.get("input"),
            preview=options.get("preview"),
            tenant=options.get("tenant"),
        )


class MgmtLoginOptions:
    def __init__(
        self,
        stepup: bool = False,
        mfa: bool = False,
        revoke_other_sessions: Optional[bool] = None,
        custom_claims: Optional[dict] = None,
        jwt: Optional[str] = None,
        refresh_duration: Optional[int] = None,
    ):
        self.stepup = stepup
        self.custom_claims = custom_claims
        self.mfa = mfa
        self.revoke_other_sessions = revoke_other_sessions
        self.jwt = jwt
        self.refresh_duration = refresh_duration


def is_jwt_required(lgo: MgmtLoginOptions) -> bool:
    return lgo is not None and (lgo.stepup or lgo.mfa)


class MgmtUserRequest:
    def __init__(
        self,
        name: Optional[str] = None,
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        email_verified: Optional[bool] = None,
        phone_verified: Optional[bool] = None,
        sso_app_id: Optional[str] = None,
    ):
        self.name = name
        self.given_name = given_name
        self.middle_name = middle_name
        self.family_name = family_name
        self.phone = phone
        self.email = email
        self.email_verified = email_verified
        self.phone_verified = phone_verified
        self.sso_app_id = sso_app_id

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "givenName": self.given_name,
            "middleName": self.middle_name,
            "familyName": self.family_name,
            "phone": self.phone,
            "email": self.email,
            "emailVerified": self.email_verified,
            "phoneVerified": self.phone_verified,
            "ssoAppId": self.sso_app_id,
        }


class AssociatedTenant:
    """
    Represents a tenant association for a User or Access Key. The tenant_id is required to denote
    which tenant the user or access key belongs to. The role_names array is an optional list of
    roles for the user or access key in this specific tenant.
    """

    def __init__(self, tenant_id: str, role_names: Optional[List[str]] = None):
        self.tenant_id = tenant_id
        self.role_names = [] if role_names is None else role_names


def associated_tenants_to_dict(associated_tenants: List[AssociatedTenant]) -> list:
    associated_tenant_list = []
    if associated_tenants:
        for associated_tenant in associated_tenants:
            associated_tenant_list.append(
                {
                    "tenantId": associated_tenant.tenant_id,
                    "roleNames": associated_tenant.role_names,
                }
            )
    return associated_tenant_list


class SAMLIDPAttributeMappingInfo:
    """
    Represents a SAML IDP attribute mapping object. use this class for mapping Descope attribute
    to the relevant SAML Assertion attributes matching your expected SP attributes names.
    """

    def __init__(self, name: str, type: str, value: str):
        self.name = name
        self.type = type
        self.value = value


def saml_idp_attribute_mapping_info_to_dict(
    attributes_mapping: Optional[List[SAMLIDPAttributeMappingInfo]] = None,
) -> list:
    attributes_mapping_list = []
    if attributes_mapping:
        for attribute_mapping in attributes_mapping:
            attributes_mapping_list.append(
                {
                    "name": attribute_mapping.name,
                    "type": attribute_mapping.type,
                    "value": attribute_mapping.value,
                }
            )
    return attributes_mapping_list


class SAMLIDPRoleGroupMappingInfo:
    """
    Represents a SAML IDP Role Group mapping object.
    """

    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name


def saml_idp_role_group_mapping_info_to_dict(
    role_groups_mapping: Optional[List[SAMLIDPRoleGroupMappingInfo]] = None,
) -> list:
    role_groups_mapping_list = []
    if role_groups_mapping:
        for group_mapping in role_groups_mapping:
            role_groups_mapping_list.append(
                {
                    "id": group_mapping.id,
                    "name": group_mapping.name,
                }
            )
    return role_groups_mapping_list


class SAMLIDPGroupsMappingInfo:
    """
    Represents a SAML IDP Descope roles to SP groups mapping object. use this class for mapping Descope roles
    to your SP groups.
    """

    def __init__(
        self,
        name: str,
        type: str,
        filter_type: str,
        value: str,
        roles: List[SAMLIDPRoleGroupMappingInfo],
    ):
        self.name = name
        self.type = type
        self.filter_type = filter_type
        self.value = value
        self.roles = roles


def saml_idp_groups_mapping_info_to_dict(
    groups_mapping: Optional[List[SAMLIDPGroupsMappingInfo]] = None,
) -> list:
    groups_mapping_list = []
    if groups_mapping:
        for group_mapping in groups_mapping:
            groups_mapping_list.append(
                {
                    "name": group_mapping.name,
                    "type": group_mapping.type,
                    "filterType": group_mapping.filter_type,
                    "value": group_mapping.value,
                    "roles": saml_idp_role_group_mapping_info_to_dict(
                        group_mapping.roles
                    ),
                }
            )
    return groups_mapping_list


class Sort:
    """
    Represents a sort object.
    """

    def __init__(self, field: str, desc: Optional[bool] = False):
        self.field = field
        self.desc = desc


def sort_to_dict(sort: List[Sort]) -> list:
    sort_list = []
    if sort:
        for s in sort:
            sort_list.append(
                {
                    "field": s.field,
                    "desc": s.desc,
                }
            )
    return sort_list


class DescoperRole(Enum):
    """Represents a Descoper role."""

    ADMIN = "admin"
    DEVELOPER = "developer"
    SUPPORT = "support"
    AUDITOR = "auditor"


class DescoperAttributes:
    """
    Represents Descoper attributes, such as name and email/phone.
    """

    def __init__(
        self,
        display_name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ):
        self.display_name = display_name
        self.email = email
        self.phone = phone

    def to_dict(self) -> dict:
        return {
            "displayName": self.display_name,
            "email": self.email,
            "phone": self.phone,
        }


class DescoperTagRole:
    """
    Represents a Descoper tags to role mapping.
    """

    def __init__(
        self,
        tags: Optional[List[str]] = None,
        role: Optional[DescoperRole] = None,
    ):
        self.tags = tags if tags is not None else []
        self.role = role

    def to_dict(self) -> dict:
        return {
            "tags": self.tags,
            "role": self.role.value if self.role else None,
        }


class DescoperProjectRole:
    """
    Represents a Descoper projects to role mapping.
    """

    def __init__(
        self,
        project_ids: Optional[List[str]] = None,
        role: Optional[DescoperRole] = None,
    ):
        self.project_ids = project_ids if project_ids is not None else []
        self.role = role

    def to_dict(self) -> dict:
        return {
            "projectIds": self.project_ids,
            "role": self.role.value if self.role else None,
        }


class DescoperRBAC:
    """
    Represents Descoper RBAC configuration.
    """

    def __init__(
        self,
        is_company_admin: bool = False,
        tags: Optional[List[DescoperTagRole]] = None,
        projects: Optional[List[DescoperProjectRole]] = None,
    ):
        self.is_company_admin = is_company_admin
        self.tags = tags if tags is not None else []
        self.projects = projects if projects is not None else []

    def to_dict(self) -> dict:
        return {
            "isCompanyAdmin": self.is_company_admin,
            "tags": [t.to_dict() for t in self.tags],
            "projects": [p.to_dict() for p in self.projects],
        }


class DescoperCreate:
    """
    Represents a Descoper to be created.
    """

    def __init__(
        self,
        login_id: str,
        attributes: Optional[DescoperAttributes] = None,
        send_invite: bool = False,
        rbac: Optional[DescoperRBAC] = None,
    ):
        self.login_id = login_id
        self.attributes = attributes
        self.send_invite = send_invite
        self.rbac = rbac

    def to_dict(self) -> dict:
        return {
            "loginId": self.login_id,
            "attributes": self.attributes.to_dict() if self.attributes else None,
            "sendInvite": self.send_invite,
            "rbac": self.rbac.to_dict() if self.rbac else None,
        }


def descopers_to_dict(descopers: List[DescoperCreate]) -> list:
    return [d.to_dict() for d in descopers]


class MgmtKeyStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class MgmtKeyProjectRole:
    def __init__(self, project_ids: List[str], roles: List[str]):
        self.project_ids = project_ids
        self.roles = roles

    def to_dict(self) -> dict:
        return {
            "projectIds": self.project_ids,
            "roles": self.roles,
        }


class MgmtKeyTagRole:
    def __init__(self, tags: List[str], roles: List[str]):
        self.tags = tags
        self.roles = roles

    def to_dict(self) -> dict:
        return {
            "tags": self.tags,
            "roles": self.roles,
        }


class MgmtKeyReBac:
    def __init__(
        self,
        company_roles: Optional[List[str]] = None,
        project_roles: Optional[List[MgmtKeyProjectRole]] = None,
        tag_roles: Optional[List[MgmtKeyTagRole]] = None,
    ):
        self.company_roles = company_roles
        self.project_roles = project_roles
        self.tag_roles = tag_roles

    def to_dict(self) -> dict:
        res: dict = {}
        if self.company_roles is not None:
            res["companyRoles"] = self.company_roles
        if self.project_roles is not None:
            res["projectRoles"] = [pr.to_dict() for pr in self.project_roles]
        if self.tag_roles is not None:
            res["tagRoles"] = [tr.to_dict() for tr in self.tag_roles]
        return res
