# Changelog

## [2.9.0](https://github.com/descope/python-sdk/compare/descope-2.8.0...descope-2.9.0) (2026-06-28)


### Features

* **mgmt:** add engine management API ([#1596](https://github.com/descope/python-sdk/issues/1596)) ([d55b3ec](https://github.com/descope/python-sdk/commit/d55b3ec2a5fcb8bb6f81623c114aeec36671063d))

## [2.8.0](https://github.com/descope/python-sdk/compare/descope-2.7.0...descope-2.8.0) (2026-06-28)


### Features

* **webauthn:** add mfa option to passkey enrollment (update) ([#1594](https://github.com/descope/python-sdk/issues/1594)) ([dc94421](https://github.com/descope/python-sdk/commit/dc94421625948a657ff5debca1c03d337fb07545))

## [2.7.0](https://github.com/descope/python-sdk/compare/descope-2.6.0...descope-2.7.0) (2026-06-27)


### Features

* **outbound:** add token/api-key upload and connection-status list methods ([#1591](https://github.com/descope/python-sdk/issues/1591)) ([2a2a090](https://github.com/descope/python-sdk/commit/2a2a090709691bc53d81e0320966fa091b9d1241))
* **sdk:** add async client (DescopeClientAsync) ([#1572](https://github.com/descope/python-sdk/issues/1572)) ([e0f053f](https://github.com/descope/python-sdk/commit/e0f053fb348afaf3163a081c33f540b8af713a6a))

## [2.6.0](https://github.com/descope/python-sdk/compare/descope-2.5.0...descope-2.6.0) (2026-06-22)


### Features

* **http:** also retry on transient status code 520 ([#1581](https://github.com/descope/python-sdk/issues/1581)) ([2de7f59](https://github.com/descope/python-sdk/commit/2de7f5933b421edbb841da05ad4f73c1c2af0892))
* **otp:** add mfa option to OTP update phone/email ([#1578](https://github.com/descope/python-sdk/issues/1578)) ([2fbbd8a](https://github.com/descope/python-sdk/commit/2fbbd8ae93e6dd6c062e2af48bfdf3c28bfb6779))
* **tenant:** add optional user_id/login_id actor to generate_sso_configuration_link ([#1573](https://github.com/descope/python-sdk/issues/1573)) ([b3c5649](https://github.com/descope/python-sdk/commit/b3c564929589e964d0c5814b77b7d15f2551162d))

## [2.5.0](https://github.com/descope/python-sdk/compare/descope-2.4.0...descope-2.5.0) (2026-06-12)


### Features

* add locale to invite and invite_batch ([#1557](https://github.com/descope/python-sdk/issues/1557)) ([536c4e3](https://github.com/descope/python-sdk/commit/536c4e30a79a5deda1c3d0c546a9c061353a2e90))
* **sso:** add idp_entity_id to SSOSAMLSettingsByMetadata ([#1567](https://github.com/descope/python-sdk/issues/1567)) ([970de0a](https://github.com/descope/python-sdk/commit/970de0a12830d986f44ef4adc6b8f519c6922715))


### Reverts

* "chore(deps): update dependency mypy to v2.0.0" ([#1552](https://github.com/descope/python-sdk/issues/1552)) ([03c195a](https://github.com/descope/python-sdk/commit/03c195a7cc58f8596171cfb996b3fa5e880fba7a))

## [2.4.0](https://github.com/descope/python-sdk/compare/descope-2.3.0...descope-2.4.0) (2026-05-16)


### Features

* add FGA mappings support to SSO tenant settings ([#1539](https://github.com/descope/python-sdk/issues/1539)) ([95bade5](https://github.com/descope/python-sdk/commit/95bade52a43e2dfd5a1a317392d701440117556f))

## [2.3.0](https://github.com/descope/python-sdk/compare/descope-2.2.0...descope-2.3.0) (2026-05-15)


### Features

* add license handshake and x-descope-license header ([#1537](https://github.com/descope/python-sdk/issues/1537)) ([0ab28eb](https://github.com/descope/python-sdk/commit/0ab28ebe9520b0f81055d6492cc77df5064d81c4))

## [2.2.0](https://github.com/descope/python-sdk/compare/descope-2.1.0...descope-2.2.0) (2026-05-13)


### Features

* add email and sso_id parameters to generate_sso_configuration_link ([#1534](https://github.com/descope/python-sdk/issues/1534)) ([b56a35d](https://github.com/descope/python-sdk/commit/b56a35d92e09f771c9aec74d02c43ce21e63942e))

## [2.1.0](https://github.com/descope/python-sdk/compare/descope-2.0.0...descope-2.1.0) (2026-05-13)


### Features

* add generate_sso_configuration_link method to Tenant management ([#1530](https://github.com/descope/python-sdk/issues/1530)) ([463ff32](https://github.com/descope/python-sdk/commit/463ff32f51218c8d67bf60f5555b561f636cb62e))

## [2.0.0](https://github.com/descope/python-sdk/compare/descope-1.13.0...descope-2.0.0) (2026-05-06)


### ⚠ BREAKING CHANGES

* drop support for python 3.8 ([#1371](https://github.com/descope/python-sdk/issues/1371))
* **sdk:** migrate from requests to httpx ([#1123](https://github.com/descope/python-sdk/issues/1123))

### Features

* drop support for python 3.8 ([#1371](https://github.com/descope/python-sdk/issues/1371)) ([5114a01](https://github.com/descope/python-sdk/commit/5114a019f6bd5cfbabbebff62d873c86f50e3d06))
* **roles-permissions:** add id-based management methods and role_ids search ([#1456](https://github.com/descope/python-sdk/issues/1456)) ([3d3b0ac](https://github.com/descope/python-sdk/commit/3d3b0acf1a9b82fe4c7ceb1d9272550be6efb63a))


### Bug Fixes

* **deps:** pin pytest &lt;9 on Python 3.9 to keep lock satisfiable ([#1512](https://github.com/descope/python-sdk/issues/1512)) ([e1666ca](https://github.com/descope/python-sdk/commit/e1666ca37e6cbd91df9cd97422c4603c235af808))
* **deps:** update dependency httpx to ^0.28.0 ([#1450](https://github.com/descope/python-sdk/issues/1450)) ([4bd6275](https://github.com/descope/python-sdk/commit/4bd6275f652d74bffc8082083c4ed5318aa2f2b9))


### Reverts

* "chore(deps): update dependency pytest to &gt;=9,&lt;10" ([#1514](https://github.com/descope/python-sdk/issues/1514)) ([0f3cc5f](https://github.com/descope/python-sdk/commit/0f3cc5fa446f0a8d4fcba346c366d5cf70b16cb8))


### Code Refactoring

* **sdk:** migrate from requests to httpx ([#1123](https://github.com/descope/python-sdk/issues/1123)) ([5d4cfd5](https://github.com/descope/python-sdk/commit/5d4cfd53933dd96af1179885571b2d27cf171507))

## [1.13.0](https://github.com/descope/python-sdk/compare/descope-1.12.2...descope-1.13.0) (2026-04-20)


### Features

* impersonate stepup support ([#1064](https://github.com/descope/python-sdk/issues/1064)) ([63d051a](https://github.com/descope/python-sdk/commit/63d051a69380895d7941da1b43076e1059285e15))

## [1.12.2](https://github.com/descope/python-sdk/compare/descope-1.12.1...descope-1.12.2) (2026-04-12)


### Bug Fixes

* remove set active from set password ([#806](https://github.com/descope/python-sdk/issues/806)) ([4cd8caf](https://github.com/descope/python-sdk/commit/4cd8caf8fc51c3c9221a48639293f1c4616a9a0b))

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
