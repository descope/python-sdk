#!/usr/bin/env bash

CURRENT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Run detect-secrets
#lint_find_secrets() {
	echo "- Running secrets check"
	INSTALLED_SECRETS_VERSION="$(gitleaks version)"
	if [[ -z $INSTALLED_SECRETS_VERSION ]]; then
		echo "Installing gitleaks for the first time..."
		brew install gitleaks
		echo "Done installing gitleaks"
	fi
	echo "  - Finding leaks in git log"
	gitleaks detect -v --redact  -c ${CURRENT_DIR}/gitleaks.toml
	if [ $? -ne 0 ]; then
		exit 1
	fi
	echo "  - Finding leaks in local repo"
	gitleaks detect --no-git -v --redact -c ${CURRENT_DIR}/gitleaks.toml
	if [ $? -ne 0 ]; then
		exit 1
	fi
	echo "- Secrets check passed sucessfully!"
#}
