#!/bin/sh

set -ex
d="/data/adb/testkey-signer/backup"
inactive=""
if [ "$(getprop ro.boot.slot_suffix)" = "_a" ]; then
    inactive="_b"
elif [ "$(getprop ro.boot.slot_suffix)" = "_b" ]; then
    inactive="_a"
fi
mkdir -p "$d" || true
for part in init_boot vbmeta boot vendor_boot dtbo recovery; do
    dev="/dev/block/by-name/$part$inactive"
    if [ -e "$dev" ]; then
        dd if="$dev" of="$d/$part.img"
    fi
done
echo Backup done.
ls -l "$d"
