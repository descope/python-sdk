from typing import List


class MgmtV1:
    # tenant
    tenant_create_path = "/v1/mgmt/tenant/create"
    tenant_update_path = "/v1/mgmt/tenant/update"
    tenant_delete_path = "/v1/mgmt/tenant/delete"
    tenant_load_all_path = "/v1/mgmt/tenant/all"

    # user
    user_create_path = "/v1/mgmt/user/create"
    user_update_path = "/v1/mgmt/user/update"
    user_delete_path = "/v1/mgmt/user/delete"
    user_delete_all_test_users_path = "/v1/mgmt/user/test/delete/all"
    user_load_path = "/v1/mgmt/user"
    users_search_path = "/v1/mgmt/user/search"
    user_update_status_path = "/v1/mgmt/user/update/status"
    user_update_email_path = "/v1/mgmt/user/update/email"
    user_update_phone_path = "/v1/mgmt/user/update/phone"
    user_update_name_path = "/v1/mgmt/user/update/name"
    user_update_picture_path = "/v1/mgmt/user/update/picture"
    user_update_custom_attribute_path = "/v1/mgmt/user/update/customAttribute"
    user_add_role_path = "/v1/mgmt/user/update/role/add"
    user_remove_role_path = "/v1/mgmt/user/update/role/remove"
    user_add_tenant_path = "/v1/mgmt/user/update/tenant/add"
    user_remove_tenant_path = "/v1/mgmt/user/update/tenant/remove"
    user_generate_otp_for_test_path = "/v1/mgmt/tests/generate/otp"
    user_generate_magic_link_for_test_path = "/v1/mgmt/tests/generate/magiclink"
    user_generate_enchanted_link_for_test_path = "/v1/mgmt/tests/generate/enchantedlink"

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
    flow_import_path = "/v1/mgmt/flow/import"
    flow_export_path = "/v1/mgmt/flow/export"

    # theme
    theme_import_path = "/v1/mgmt/theme/import"
    theme_export_path = "/v1/mgmt/theme/export"

    # group
    group_load_all_path = "/v1/mgmt/group/all"
    group_load_all_for_member_path = "/v1/mgmt/group/member/all"
    group_load_all_group_members_path = "/v1/mgmt/group/members"


class AssociatedTenant:
    """
    Represents a tenant association for a User or Access Key. The tenant_id is required to denote
    which tenant the user or access key belongs to. The role_names array is an optional list of
    roles for the user or access key in this specific tenant.
    """

    def __init__(self, tenant_id: str, role_names: List[str] = None):
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
