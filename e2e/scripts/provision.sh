#!/usr/bin/env bash

set -eu

# This script runs on the first boot of the VM.
echo "Setting hostname..."
hostname="$(lsb_release -cs)-$(openssl rand -hex 4)"
hostnamectl set-hostname "$hostname"

echo "Adding hostname to hosts file..."
echo "127.0.0.1 $hostname" >> /etc/hosts

echo "Updating authorized_keys for root..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cp /home/azureuser/.ssh/authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

echo "Allowing password authentication via SSH..."
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/g' /etc/ssh/sshd_config

echo "Updating DNS resolver to use AD DNS..."
echo "DNS=10.1.0.4" >> /etc/systemd/resolved.conf
systemctl restart systemd-resolved

rm -f /usr/lib/NetworkManager/conf.d/10-globally-managed-devices.conf
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl restart NetworkManager
nmcli dev connect eth0

echo "Updating netplan configuration to use NetworkManager..."
cat <<EOF > /etc/netplan/01-network-manager-all.yaml
network:
  version: 2
  renderer: NetworkManager
EOF
chmod 600 /etc/netplan/01-network-manager-all.yaml

echo "Applying netplan configuration..."
netplan apply
