#!/bin/sh

# Build a test container running polkitd and a mock systemd
# At runtime passing yes or no to the container will always allow or always deny authorization
# Other parameters allows to control systemd time answers:
# no_startup_time, invalid_startup_time, no_nextrefresh_time, invalid_nextrefresh_time
set -eu

rootdir="$(realpath $(dirname $(realpath $0))/../../../)"
cd ${rootdir}
docker build -t ghcr.io/ubuntu/adsys/systemdaemons:0.1 -f cmd/integration_tests/systemdaemons/Dockerfile .
