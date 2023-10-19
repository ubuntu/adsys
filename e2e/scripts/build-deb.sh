#!/bin/bash

set -euo pipefail

# This script is executed within the container as root.  It assumes
# that source code with debian packaging files can be found at
# /source-ro and that resulting packages are written to /output after
# successful build.  These directories are mounted as docker volumes to
# allow files to be exchanged between the host and the container.
#
# Based on https://github.com/cgzones/container-deb-builder

if [ -t 0 ] && [ -t 1 ]; then
    Blue='\033[0;34m'
    Reset='\033[0m'
else
    Blue=
    Reset=
fi

function log {
    echo -e "[${Blue}*${Reset}] $1"
}

# Remove directory owned by _apt
trap "rm -rf /var/cache/apt/archives/partial" EXIT

log "Updating image"
apt-get update
apt-get upgrade -y --no-install-recommends
apt-mark minimize-manual -y
apt-get autoremove -y

log "Cleaning apt package cache"
apt-get autoclean

# Make read-write copy of source code
log "Copying source directory"
mkdir -p /build
cp -a /source-ro /build/source
cd /build/source

# Patch debian directory to satisfy build dependencies
log "Patching debian/ directory"
codename=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
if [ -f /patches/${codename}.patch ]; then
    if ! patch --ignore-whitespace --no-backup-if-mismatch -r /tmp/rejected -p1 < /patches/${codename}.patch; then
        log "Rejected hunks:"
        cat /tmp/rejected
        exit 1
    fi
fi

# Install build dependencies
log "Installing build dependencies"
DEBIAN_FRONTEND=noninteractive apt-get -y build-dep .

# Build packages
log "Building package"
DEB_BUILD_OPTIONS=nocheck debuild -b -uc -us

mkdir -p /output/${codename}
# Copy packages to output dir with user's permissions
if [ -n "${USER+x}" ] && [ -n "${GROUP+x}" ]; then
    chown -R "${USER}:${GROUP}" /build /output
fi

cp -a /build/*.deb /output/${codename}
ls -l -A --color=auto -h /output

log "Finished"
