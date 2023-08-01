#!/usr/bin/env bash

set -o pipefail
set -e

PKG="rpm"

[[ $1 =~ debian ]] && PKG="deb"
[[ $1 =~ ubuntu ]] && PKG="deb"

make

version=$(awk -F\" '/^version/ {print $2}' Cargo.toml)

rm -rf geneos-xtender*.rpm
rm -rf geneos-xtender*.deb

pkg --arch x86_64 --rpm --name geneos-xtender --version "$version" package_rpm.yaml
pkg --arch x86_64 --deb --name geneos-xtender --version "$version" package_deb.yaml

docker build -t geneos-xtender-bats-"$1" --platform=linux/amd64 --build-arg IMAGE="$1" --build-arg PKG="$PKG" -f tests/integration_tests/Dockerfile . && docker run --platform=linux/amd64 --rm -it geneos-xtender-bats-"$1"
