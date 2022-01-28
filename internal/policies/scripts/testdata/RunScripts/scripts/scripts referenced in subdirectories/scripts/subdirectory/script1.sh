#!/bin/sh

script=$(realpath $0)
# Our scripts are in: user/foo/scripts/scripts. This is is in subdirectory
# We want to write our golden file in user/foo/.
path=$(dirname $(dirname $(dirname $(dirname ${script}))))

mkdir -p "${path}/golden/"
echo $(basename $0) >> "${path}/golden/order"
