# Changelog

## [1.12.1](https://github.com/descope/python-sdk/compare/descope-1.12.0...descope-1.12.1) (2026-03-29)


### Bug Fixes

* add locale to LoginOptions and fix password sign_in docstring ([#798](https://github.com/descope/python-sdk/issues/798)) ([ad09985](https://github.com/descope/python-sdk/commit/ad09985b5980201817b229f41c264c06ab94a3f5))

## [1.12.0](https://github.com/descope/python-sdk/compare/descope-1.11.0...descope-1.12.0) (2026-03-23)


### Features

* add batch operations for roles and permissions ([#789](https://github.com/descope/python-sdk/issues/789)) ([ce3021f](https://github.com/descope/python-sdk/commit/ce3021ffebd440773398fdc1c9e57a70c1887afc))
* **http:** retry requests on transient error status codes ([#792](https://github.com/descope/python-sdk/issues/792)) ([011fadf](https://github.com/descope/python-sdk/commit/011fadfd43baf8588eb646cc372995f6fe838ac2))
* **security:** enable cookie secure flag, fix redos, add jwt decode warn ([#781](https://github.com/descope/python-sdk/issues/781)) ([90af115](https://github.com/descope/python-sdk/commit/90af11503675b48961e67d44dbd5dcdbce66fa2a))
* **sso-app:** add default signature method ([#787](https://github.com/descope/python-sdk/issues/787)) ([e79b0b8](https://github.com/descope/python-sdk/commit/e79b0b82a4de63c7efd90d44cc2180cf278f4011))

## [1.11.0](https://github.com/descope/python-sdk/compare/descope-1.10.1...descope-1.11.0) (2026-03-10)


### Features

* add selectedTenant to AccessKeyLoginOptions for access key exchange ([#768](https://github.com/descope/python-sdk/issues/768)) ([0f60183](https://github.com/descope/python-sdk/commit/0f601835bad4c2136c18852b8d6458b687b2efe8))
* add update_default_roles method to Tenant management ([#779](https://github.com/descope/python-sdk/issues/779)) ([c5d5d37](https://github.com/descope/python-sdk/commit/c5d5d37486889971a2cbc738efc2368fed49119f))
* **authz:** route who_can_access and what_can_target_access through FGA cache ([#767](https://github.com/descope/python-sdk/issues/767)) ([b49d937](https://github.com/descope/python-sdk/commit/b49d937534beb429312c1d78546255c056179453))

## [1.10.1](https://github.com/descope/python-sdk/compare/descope-1.10.0...descope-1.10.1) (2026-02-18)


### Bug Fixes

* add loginHint and forceAuthn to saml start ([1c197eb](https://github.com/descope/python-sdk/commit/1c197ebcd71d9fde02ddb15e6790782d30617f54))
* add loginHint and forceAuthn to saml start ([#765](https://github.com/descope/python-sdk/issues/765)) ([1c197eb](https://github.com/descope/python-sdk/commit/1c197ebcd71d9fde02ddb15e6790782d30617f54))


### Documentation

* fix external groups functions docs ([#748](https://github.com/descope/python-sdk/issues/748)) ([2eff8cb](https://github.com/descope/python-sdk/commit/2eff8cbeb749330217dc92133096dc7b2bed95ee))

## [1.10.0](https://github.com/descope/python-sdk/compare/descope-1.9.1...descope-1.10.0) (2026-01-19)


### Features

* access key custom attributes CRU ([#746](https://github.com/descope/python-sdk/issues/746)) ([25e6de9](https://github.com/descope/python-sdk/commit/25e6de943288d4e2ea69fa174c566b0de7530f7f))


### Bug Fixes

* recalculate SSO Mappings ([89a2a21](https://github.com/descope/python-sdk/commit/89a2a21a107ea70a82dc76ff8479e1a71102d2c0))

## [1.9.1](https://github.com/descope/python-sdk/compare/descope-1.9.0...descope-1.9.1) (2026-01-15)


### Bug Fixes

* add enforcessolist and appids to tenant create and update ([#734](https://github.com/descope/python-sdk/issues/734)) ([2039053](https://github.com/descope/python-sdk/commit/203905381f0345906c359f2d9037c4cc8a2c32e5))
* add group priority support ([#742](https://github.com/descope/python-sdk/issues/742)) ([262ad0f](https://github.com/descope/python-sdk/commit/262ad0f7ae3fda2873a684b9956071e889d67595))

## [1.9.0](https://github.com/descope/python-sdk/compare/descope-1.8.0...descope-1.9.0) (2025-12-30)


### Features

* Add management flow operations, including sync and async runs and result functions ([#727](https://github.com/descope/python-sdk/issues/726)) ([ba2a163](https://github.com/descope/python-sdk/commit/ba2a1639f06c599ae97899e30fea3bf248be2c8b))

## [1.8.0](https://github.com/descope/python-sdk/compare/descope-1.7.14...descope-1.8.0) (2025-12-25)


### Features

* add opt-in verbose mode for capturing HTTP response metadata ([#718](https://github.com/descope/python-sdk/issues/718)) ([91b364a](https://github.com/descope/python-sdk/commit/91b364a999c40c6ea13b1761398d5f7200c67831))
