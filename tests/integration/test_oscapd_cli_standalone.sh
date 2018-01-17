#!/bin/bash

# calls in this test should not require oscapd to be running

$PYTHON $BIN/oscapd-cli
[ $? -eq 2 ] || exit 1
$PYTHON $BIN/oscapd-cli --version || exit 1
$PYTHON $BIN/oscapd-cli -v || exit 1
$PYTHON $BIN/oscapd-cli --help || exit 1
$PYTHON $BIN/oscapd-cli -h || exit 1

useradd testuser
out=$(su testuser -c "$PYTHON $BIN/oscapd-cli status 2>&1")
rv=$?
userdel -r testuser
[ $rv -ne 0 ] || exit 1
grep -iq "traceback" <<< "$out"
[ $? -ne 0 ] || exit 1
