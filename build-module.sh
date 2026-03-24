#!/bin/sh

set -e
./build-android.sh
rm -rf module_dist || true
cp -r module module_dist
cp target/aarch64-linux-android/release/testkey-signer module_dist/testkey-signer

n=$(git rev-list --count HEAD)
filename=testkey-signer-${n}.zip
(cd module_dist; zip -r ../${filename} .)
echo Zip written to ${filename}