#!/bin/sh

set -ex
d="/data/adb/testkey-signer/backup"
for part in init_boot vbmeta boot vendor_boot dtbo recovery; do
    dev="/dev/block/by-name/$part$(getprop ro.boot.slot_suffix)"
    if [ -e "$dev" ]; then
        dd of="$dev" if="$d/$part.img"
    fi
done
echo Restore done.
