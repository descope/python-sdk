from typing import List


class MgmtV1:
    # tenant
    tenantCreatePath = "/v1/mgmt/tenant/create"
    tenantUpdatePath = "/v1/mgmt/tenant/update"
    tenantDeletePath = "/v1/mgmt/tenant/delete"
    tenantLoadAllPath = "/v1/mgmt/tenant/all"

    # user
    userCreatePath = "/v1/mgmt/user/create"
    userUpdatePath = "/v1/mgmt/user/update"
    userDeletePath = "/v1/mgmt/user/delete"
    userLoadPath = "/v1/mgmt/user"
    usersSearchPath = "/v1/mgmt/user/search"
    userUpdateStatusPath = "/v1/mgmt/user/update/status"
    userUpdateEmailPath = "/v1/mgmt/user/update/email"
    userUpdatePhonePath = "/v1/mgmt/user/update/phone"
    userUpdateNamePath = "/v1/mgmt/user/update/name"
    userAddRolePath = "/v1/mgmt/user/update/role/add"
    userRemoveRolePath = "/v1/mgmt/user/update/role/remove"
    userAddTenantPath = "/v1/mgmt/user/update/tenant/add"
    userRemoveTenantPath = "/v1/mgmt/user/update/tenant/remove"

    # access key
    accessKeyCreatePath = "/v1/mgmt/accesskey/create"
    accessKeyLoadPath = "/v1/mgmt/accesskey"
    accessKeysSearchPath = "/v1/mgmt/accesskey/search"
    accessKeyUpdatePath = "/v1/mgmt/accesskey/update"
    accessKeyDeactivatePath = "/v1/mgmt/accesskey/deactivate"
    accessKeyActivatePath = "/v1/mgmt/accesskey/activate"
    accessKeyDeletePath = "/v1/mgmt/accesskey/delete"

    # sso
    ssoConfigurePath = "/v1/mgmt/sso/settings"
    ssoMetadataPath = "/v1/mgmt/sso/metadata"
    ssoMappingPath = "/v1/mgmt/sso/mapping"

    # jwt
    updateJwt = "/v1/mgmt/jwt/update"

    # permission
    permissionCreatePath = "/v1/mgmt/permission/create"
    permissionUpdatePath = "/v1/mgmt/permission/update"
    permissionDeletePath = "/v1/mgmt/permission/delete"
    permissionLoadAllPath = "/v1/mgmt/permission/all"

    # role
    roleCreatePath = "/v1/mgmt/role/create"
    roleUpdatePath = "/v1/mgmt/role/update"
    roleDeletePath = "/v1/mgmt/role/delete"
    roleLoadAllPath = "/v1/mgmt/role/all"

    # group
    groupLoadAllPath = "/v1/mgmt/group/all"
    groupLoadAllForMemberPath = "/v1/mgmt/group/member/all"
    groupLoadAllGroupMembersPath = "/v1/mgmt/group/members"


class AssociatedTenant:
    """
    Represents a tenant association for a User or Access Key. The tenant_id is required to denote
    which tenant the user or access key belongs to. The role_names array is an optional list of
    roles for the user or access key in this specific tenant.
    """

    def __init__(self, tenant_id: str, role_names: List[str] = []):
        self.tenant_id = tenant_id
        self.role_names = role_names


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
