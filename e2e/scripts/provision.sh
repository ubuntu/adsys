#!/usr/bin/env bash

set -eu

echo "Create global authorized_keys file..."
cp /home/azureuser/.ssh/authorized_keys /etc/ssh/authorized_keys
chmod 644 /etc/ssh/authorized_keys # needs to be world-readable
echo "AuthorizedKeysFile /etc/ssh/authorized_keys" >> /etc/ssh/sshd_config

echo "Configure PAM to create home directories on first login..."
pam-auth-update --enable mkhomedir

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
