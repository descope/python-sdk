#!/usr/bin/env bash

CURRENT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
GITLEAKS_VERSION="v8.8.11"

# Run detect-secrets
echo "- Running secrets check"
INSTALLED_SECRETS_VERSION="$(docker inspect ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION)"
if [[ -z $INSTALLED_SECRETS_VERSION ]]; then
	echo "Installing gitleaks for the first time..."
	git pull ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION
	echo "Done installing gitleaks"
fi
echo "  - Finding leaks in git log"
docker run --rm -v ${CURRENT_DIR}:/conf -v ${PWD}:/code ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION detect -v --redact --source="/code" -c /conf/gitleaks.toml
if [ $? -ne 0 ]; then
	exit 1
fi
echo "  - Finding leaks in local repo"
docker run --rm -v ${CURRENT_DIR}:/conf -v ${PWD}:/code ghcr.io/zricethezav/gitleaks:$GITLEAKS_VERSION detect --no-git -v --redact --source="/code" -c /conf/gitleaks.toml
if [ $? -ne 0 ]; then
	exit 1
fi
echo "- Secrets check passed sucessfully!"
