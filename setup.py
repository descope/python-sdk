import setuptools

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="descope-auth",
    version="0.0.1",
    author="Descope",
    author_email="guyp@descope.com",
    description="Descope Python SDK package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/descope/python-sdk",
    project_urls={
        "Bug Tracker": "https://github.com/descope/python-sdk/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
    install_requires=["requests", "PyJWT", "cryptography", "email-validator"],
)
