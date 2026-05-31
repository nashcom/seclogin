#!/bin/bash
# Install runtime/provisioning dependencies for seclogin
# NOTE: compilation is done inside an Alpine container (see build_alpine.sh)
# Only oathtool and qrencode are needed on the host for TOTP provisioning

set -e

# packages per distro family
APT_PACKAGES="oathtool qrencode"
RPM_PACKAGES="oathtool qrencode"

error()
{
    echo "ERROR: $*" >&2
    exit 1
}

header()
{
    echo
    echo "------------------------------------------------------------"
    echo " $*"
    echo "------------------------------------------------------------"
    echo
}

if [ "$(id -u)" -ne 0 ]; then
    error "Run as root (sudo $0)"
fi

if command -v apt-get > /dev/null 2>&1; then

    header "Detected apt (Debian/Ubuntu)"
    apt-get update -qq
    apt-get install -y $APT_PACKAGES

elif command -v dnf > /dev/null 2>&1; then

    header "Detected dnf (Fedora/RHEL 8+)"
    dnf install -y $RPM_PACKAGES

elif command -v yum > /dev/null 2>&1; then

    header "Detected yum (RHEL/CentOS)"
    yum install -y $RPM_PACKAGES

else
    error "No supported package manager found (apt/dnf/yum)"
fi

header "Installed versions"

oathtool  --version 2>&1 | head -1
qrencode  --version 2>&1 | head -1

echo
echo "All dependencies installed."
echo "Build binary with:          ./build_alpine.sh"
echo "Provision TOTP secret with: sudo ./create_totp.sh <account>"
echo
