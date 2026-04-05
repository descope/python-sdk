# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/descope/python-sdk/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                |    Stmts |     Miss |   Cover |   Missing |
|------------------------------------ | -------: | -------: | ------: | --------: |
| descope/auth.py                     |      261 |        6 |     98% |320, 352-354, 394, 519, 554 |
| descope/authmethod/enchantedlink.py |       92 |        2 |     98% |  202, 204 |
| descope/authmethod/magiclink.py     |      103 |        4 |     96% |233, 235, 258, 260 |
| descope/authmethod/otp.py           |      110 |        4 |     96% |330, 332, 355, 357 |
| descope/common.py                   |      116 |        1 |     99% |       187 |
| descope/descope\_client.py          |      193 |        5 |     97% |56, 120, 151, 235, 332 |
| descope/jwt\_common.py              |       51 |        1 |     98% |       112 |
| descope/management/audit.py         |       44 |       11 |     75% |74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94 |
| descope/management/common.py        |      378 |        1 |     99% |        86 |
| descope/management/role.py          |       36 |        1 |     97% |       230 |
| descope/management/user.py          |      377 |       15 |     96% |68-73, 801, 1156, 1158, 1160, 1908, 1960, 2003, 2005, 2007 |
|                           **TOTAL** | **3108** |   **51** | **98%** |           |

28 files skipped due to complete coverage.


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