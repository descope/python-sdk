class MgmtV1:
    # tenant
    tenantCreatePath = "/v1/mgmt/tenant/create"
    tenantUpdatePath = "/v1/mgmt/tenant/update"
    tenantDeletePath = "/v1/mgmt/tenant/delete"

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

    # deprecated
    ssoRoleMappingPath = "/v1/mgmt/sso/roles"

    # jwt
    updateJwt = "/v1/mgmt/jwt/update"
