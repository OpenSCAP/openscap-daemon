#!/bin/bash

set -e

TMPDIR=$(mktemp -d)
cp -r "$DATA_DIR_TEMPLATE" "$TMPDIR"

export OSCAPD_CONFIG_FILE="$TMPDIR/data_dir_template/config.ini"
export OSCAPD_SESSION_BUS="1"

$PYTHON $BIN/oscapd &
OSCAPD_PID=$!

sleep 2

$PYTHON $BIN/oscapd-cli task

kill $OSCAPD_PID

rm -rf "$TMPDIR"
