#!/usr/bin/env bash

set -eu

# This script runs on the first boot of the VM.
echo "Setting hostname..."
hostname="$(lsb_release -cs)-$(openssl rand -hex 2)"
hostnamectl set-hostname "$hostname"

echo "Adding hostname to hosts file..."
echo "127.0.0.1 $hostname" >> /etc/hosts

# These overrides disable password authentication which we explicitly enabled
# during provisioning. Since they take precedence over the main sshd_config we
# have to remove them.
echo "Removing cloud-init ssh configuration overrides..."
rm -rf /etc/ssh/sshd_config.d
systemctl restart ssh
