#!/usr/bin/env bash

set -eu

echo "Create global authorized_keys file..."
cp /home/azureuser/.ssh/authorized_keys /etc/ssh/authorized_keys
chmod 644 /etc/ssh/authorized_keys # needs to be world-readable
echo "AuthorizedKeysFile /etc/ssh/authorized_keys" >> /etc/ssh/sshd_config

echo "Configure PAM to create home directories on first login..."
pam-auth-update --enable mkhomedir

echo "Configure PAM to register user sessions in the systemd control group hierarchy..."
pam-auth-update --enable systemd

echo "Enabling keyboard-interactive authentication for domain users..."
sed -iE 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -iE 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config

echo "Installing additional required packages..."
# Work around an issue where the cifs kernel module is not available on some kernel versions
# ref: https://www.mail-archive.com/kernel-packages@lists.launchpad.net/msg514627.html
if [[ ! "$(lsmod)" =~ cifs ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y linux-modules-extra-azure
    echo "cifs" >> /etc/modules
fi

echo "Disabling unattended-upgrades to avoid unexpected dpkg frontend locks..."
systemctl disable --now unattended-upgrades

echo "Updating DNS resolver to use AD DNS..."
echo "DNS=10.1.0.4" >> /etc/systemd/resolved.conf
systemctl restart systemd-resolved

# Work around an issue on newer Ubuntu versions (starting with Jammy) where
# systemd-networkd times out due to eth0 losing connectivity shortly after boot,
# even though network works fine as reported by Azure.
if [ ! "$(lsb_release -cs)" = "focal" ]; then
    echo "Disabling misbehaving systemd-networkd-wait-online.service..."
    systemctl mask systemd-networkd-wait-online.service
fi

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
