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
