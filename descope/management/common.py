from typing import List, Optional


class MgmtV1:
    # tenant
    tenant_create_path = "/v1/mgmt/tenant/create"
    tenant_update_path = "/v1/mgmt/tenant/update"
    tenant_delete_path = "/v1/mgmt/tenant/delete"
    tenant_load_path = "/v1/mgmt/tenant"
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

    # user
    user_create_path = "/v1/mgmt/user/create"
    user_create_batch_path = "/v1/mgmt/user/create/batch"
    user_update_path = "/v1/mgmt/user/update"
    user_delete_path = "/v1/mgmt/user/delete"
    user_logout_path = "/v1/mgmt/user/logout"
    user_delete_all_test_users_path = "/v1/mgmt/user/test/delete/all"
    user_load_path = "/v1/mgmt/user"
    users_search_path = "/v1/mgmt/user/search"
    user_get_provider_token = "/v1/mgmt/user/provider/token"
    user_update_status_path = "/v1/mgmt/user/update/status"
    user_update_login_id_path = "/v1/mgmt/user/update/loginid"
    user_update_email_path = "/v1/mgmt/user/update/email"
    user_update_phone_path = "/v1/mgmt/user/update/phone"
    user_update_name_path = "/v1/mgmt/user/update/name"
    user_update_picture_path = "/v1/mgmt/user/update/picture"
    user_update_custom_attribute_path = "/v1/mgmt/user/update/customAttribute"
    user_set_role_path = "/v1/mgmt/user/update/role/set"
    user_add_role_path = "/v1/mgmt/user/update/role/add"
    user_remove_role_path = "/v1/mgmt/user/update/role/remove"
    user_add_sso_apps = "/v1/mgmt/user/update/ssoapp/add"
    user_set_sso_apps = "/v1/mgmt/user/update/ssoapp/set"
    user_remove_sso_apps = "/v1/mgmt/user/update/ssoapp/remove"
    user_set_password_path = "/v1/mgmt/user/password/set"
    user_expire_password_path = "/v1/mgmt/user/password/expire"
    user_remove_all_passkeys_path = "/v1/mgmt/user/passkeys/delete"
    user_add_tenant_path = "/v1/mgmt/user/update/tenant/add"
    user_remove_tenant_path = "/v1/mgmt/user/update/tenant/remove"
    user_generate_otp_for_test_path = "/v1/mgmt/tests/generate/otp"
    user_generate_magic_link_for_test_path = "/v1/mgmt/tests/generate/magiclink"
    user_generate_enchanted_link_for_test_path = "/v1/mgmt/tests/generate/enchantedlink"
    user_generate_embedded_link_path = "/v1/mgmt/user/signin/embeddedlink"

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

    # flow
    flow_list_path = "/v1/mgmt/flow/list"
    flow_delete_path = "/v1/mgmt/flow/delete"
    flow_import_path = "/v1/mgmt/flow/import"
    flow_export_path = "/v1/mgmt/flow/export"

    # theme
    theme_import_path = "/v1/mgmt/theme/import"
    theme_export_path = "/v1/mgmt/theme/export"

    # group
    group_load_all_path = "/v1/mgmt/group/all"
    group_load_all_for_member_path = "/v1/mgmt/group/member/all"
    group_load_all_group_members_path = "/v1/mgmt/group/members"

    # Audit
    audit_search = "/v1/mgmt/audit/search"

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
    authz_get_modified = "/v1/mgmt/authz/getmodified"

    # Project
    project_update_name = "/v1/mgmt/project/update/name"
    project_clone = "/v1/mgmt/project/clone"
    project_export = "/v1/mgmt/project/export"
    project_import = "/v1/mgmt/project/import"


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
