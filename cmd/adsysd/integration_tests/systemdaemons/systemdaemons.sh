#!/bin/sh
set -eu

# Set polkit allowance/denial for adsys
mode=${1:-default}
if [ "$mode" != "default" ]; then
    sed -e "s#<allow_any>.*#<allow_any>${mode}</allow_any>#" \
        -e "s#<allow_inactive>.*#<allow_inactive>${mode}</allow_inactive>#" \
        -e "s#<allow_active>.*#<allow_active>${mode}</allow_active>#" \
    /usr/share/polkit-1/actions.orig/com.ubuntu.adsys.policy > /usr/share/polkit-1/actions/com.ubuntu.adsys.policy
fi

# Start a system bus and run polkit from it
dbus-daemon --config-file=/dbus.conf
sleep 1
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/dbus/system_bus_socket
/usr/lib/policykit-1/polkitd