#!/bin/sh

script=$(realpath $0)
# Our scripts are in: user/foo/scripts/<scripts>.
# We want to write our golden file in user/foo/.
path=$(dirname $(dirname $(dirname ${script})))

echo $(basename $0) >> "${path}/golden"
