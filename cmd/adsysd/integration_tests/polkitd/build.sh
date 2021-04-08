#!/bin/sh

# Build a test containers running polkitd
# At runtime passing yes or no to the container will always allow or always deny authorization
set -eu

rootdir="$(realpath $(dirname $(realpath $0))/../../../../)"
cd ${rootdir}
docker build -t docker.pkg.github.com/ubuntu/adsys/polkitd:0.1 -f cmd/adsysd/integration_tests/polkitd/Dockerfile .
