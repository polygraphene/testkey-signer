#!/bin/sh
(. ./env-android.sh ; cargo build --target aarch64-linux-android --release)
