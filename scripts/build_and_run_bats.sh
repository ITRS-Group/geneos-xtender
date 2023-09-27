#!/usr/bin/env bash

set -o pipefail
set -e

make

version=$(awk -F\" '/^version/ {print $2}' Cargo.toml)

rm -rf geneos-xtender*.deb

pkg --arch x86_64 --deb --name geneos-xtender --version "$version" package_deb.yaml

docker build -t geneos-xtender-bats-"$1" --platform linux/amd64 --build-arg IMAGE="$1" -f tests/integration_tests/Dockerfile . && docker run --platform=linux/amd64 --rm -it geneos-xtender-bats-"$1"
