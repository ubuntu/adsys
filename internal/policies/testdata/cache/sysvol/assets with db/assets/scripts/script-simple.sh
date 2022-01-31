#!/bin/sh

script=$(realpath $0)
# Our scripts are in: user/foo/scripts/<stageName>.
# We want to write our execution order file in user/foo/.
path=$(dirname $(dirname $(dirname ${script})))

mkdir -p "${path}/execution"
echo $(basename $0) >> "${path}/execution/order"
