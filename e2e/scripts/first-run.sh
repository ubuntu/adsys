#!/usr/bin/env bash

set -eu

# This script runs on the first boot of the VM.
echo "Setting hostname..."
hostname="$(lsb_release -cs)-$(openssl rand -hex 4)"
hostnamectl set-hostname "$hostname"

echo "Adding hostname to hosts file..."
echo "127.0.0.1 $hostname" >> /etc/hosts
