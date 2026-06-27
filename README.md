# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/descope/python-sdk/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                |    Stmts |     Miss |   Cover |   Missing |
|---------------------------------------------------- | -------: | -------: | ------: | --------: |
| descope/\_auth\_base.py                             |      185 |        1 |     99% |        98 |
| descope/\_authmethod\_base.py                       |       13 |        1 |     92% |        15 |
| descope/\_client\_base.py                           |       89 |        3 |     97% |49, 140, 190 |
| descope/\_http\_base.py                             |       11 |        1 |     91% |         8 |
| descope/auth.py                                     |       90 |        5 |     94% |96-98, 102, 141, 174 |
| descope/auth\_async.py                              |      127 |        1 |     99% |       169 |
| descope/authmethod/\_enchantedlink\_base.py         |       51 |        4 |     92% |69, 98, 100, 102 |
| descope/authmethod/\_magiclink\_base.py             |       61 |        7 |     89% |74, 103, 105, 107, 127, 129, 131 |
| descope/authmethod/\_otp\_base.py                   |       64 |        7 |     89% |60, 97, 99, 101, 124, 126, 128 |
| descope/authmethod/enchantedlink.py                 |       48 |        2 |     96% |    42, 59 |
| descope/authmethod/enchantedlink\_async.py          |       47 |        2 |     96% |    46, 64 |
| descope/authmethod/magiclink.py                     |       53 |        2 |     96% |    46, 69 |
| descope/authmethod/magiclink\_async.py              |       51 |        2 |     96% |    50, 74 |
| descope/authmethod/otp.py                           |       55 |        1 |     98% |       112 |
| descope/authmethod/otp\_async.py                    |       53 |        1 |     98% |        74 |
| descope/authmethod/password.py                      |       49 |        1 |     98% |       119 |
| descope/authmethod/password\_async.py               |       43 |        1 |     98% |        62 |
| descope/descope\_client.py                          |      126 |        3 |     98% |   124-126 |
| descope/descope\_client\_async.py                   |      154 |        1 |     99% |       203 |
| descope/jwt\_common.py                              |       51 |        4 |     92% | 27-29, 96 |
| descope/management/\_outbound\_application\_base.py |       58 |        4 |     93% |92, 96, 98, 100 |
| descope/management/\_sso\_settings\_base.py         |       57 |        1 |     98% |         7 |
| descope/management/\_user\_base.py                  |      145 |       11 |     92% |65-70, 123, 178, 223, 225, 227 |
| descope/management/audit.py                         |       42 |       11 |     74% |75, 77, 79, 81, 83, 85, 87, 89, 91, 93, 95 |
| descope/management/audit\_async.py                  |       42 |       11 |     74% |77, 79, 81, 83, 85, 87, 89, 91, 93, 95, 97 |
| descope/management/common.py                        |      387 |        1 |     99% |        86 |
| descope/management/outbound\_application.py         |      117 |        1 |     99% |       613 |
| descope/management/outbound\_application\_async.py  |      119 |        1 |     99% |       613 |
| descope/management/role.py                          |       45 |        1 |     98% |       313 |
| descope/management/role\_async.py                   |       45 |        1 |     98% |       315 |
| descope/management/user.py                          |      242 |        4 |     98% |728, 1075, 1077, 1079 |
| descope/management/user\_async.py                   |      243 |        4 |     98% |732, 1079, 1081, 1083 |
|                                           **TOTAL** | **5170** |  **101** | **98%** |           |

59 files skipped due to complete coverage.


## Setup coverage badge

Below are examples of the badges you can use in your main branch `README` file.

### Direct image

[![Coverage badge](https://raw.githubusercontent.com/descope/python-sdk/python-coverage-comment-action-data/badge.svg)](https://htmlpreview.github.io/?https://github.com/descope/python-sdk/blob/python-coverage-comment-action-data/htmlcov/index.html)

This is the one to use if your repository is private or if you don't want to customize anything.

### [Shields.io](https://shields.io) Json Endpoint

[![Coverage badge](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/descope/python-sdk/python-coverage-comment-action-data/endpoint.json)](https://htmlpreview.github.io/?https://github.com/descope/python-sdk/blob/python-coverage-comment-action-data/htmlcov/index.html)

Using this one will allow you to [customize](https://shields.io/endpoint) the look of your badge.
It won't work with private repositories. It won't be refreshed more than once per five minutes.

### [Shields.io](https://shields.io) Dynamic Badge

[![Coverage badge](https://img.shields.io/badge/dynamic/json?color=brightgreen&label=coverage&query=%24.message&url=https%3A%2F%2Fraw.githubusercontent.com%2Fdescope%2Fpython-sdk%2Fpython-coverage-comment-action-data%2Fendpoint.json)](https://htmlpreview.github.io/?https://github.com/descope/python-sdk/blob/python-coverage-comment-action-data/htmlcov/index.html)

This one will always be the same color. It won't work for private repos. I'm not even sure why we included it.

## What is that?

This branch is part of the
[python-coverage-comment-action](https://github.com/marketplace/actions/python-coverage-comment)
GitHub Action. All the files in this branch are automatically generated and may be
overwritten at any moment.