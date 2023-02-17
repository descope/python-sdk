import platform

import pkg_resources

default_headers = {
    "Content-Type": "application/json",
    "x-descope-sdk-name": "python",
    "x-descope-sdk-python-version": platform.python_version(),
    "x-descope-sdk-version": pkg_resources.get_distribution("descope").version,
}
