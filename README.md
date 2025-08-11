# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/descope/python-sdk/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                |    Stmts |     Miss |   Cover |   Missing |
|------------------------------------ | -------: | -------: | ------: | --------: |
| descope/auth.py                     |      321 |       14 |     96% |16-17, 53-54, 96, 465-467, 583, 615, 626, 670, 705, 719, 746 |
| descope/authmethod/enchantedlink.py |       92 |        2 |     98% |  199, 201 |
| descope/authmethod/magiclink.py     |      103 |        4 |     96% |224, 226, 249, 251 |
| descope/authmethod/otp.py           |      110 |        4 |     96% |320, 322, 345, 347 |
| descope/common.py                   |      108 |        1 |     99% |       179 |
| descope/descope\_client.py          |      180 |        4 |     98% |70, 101, 185, 282 |
| descope/management/audit.py         |       43 |       11 |     74% |72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92 |
| descope/management/common.py        |      209 |        1 |     99% |       370 |
| descope/management/role.py          |       29 |        1 |     97% |       156 |
| descope/management/user.py          |      353 |       15 |     96% |70-75, 718, 1065, 1067, 1069, 1838, 1890, 1933, 1935, 1937 |
|                           **TOTAL** | **2429** |   **57** | **98%** |           |

23 files skipped due to complete coverage.


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