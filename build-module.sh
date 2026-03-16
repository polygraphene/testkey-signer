#!/bin/sh

set -e
./build-android.sh
rm -rf module_dist || true
cp -r module module_dist
cp target/aarch64-linux-android/release/testkey-signer module_dist/testkey-signer

n=$(git rev-list --count HEAD)
(cd module_dist; zip -r ../testkey-signer-${n}.zip .)