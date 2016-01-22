#!/bin/bash

# calls in this test should not require oscapd to be running

$PYTHON $BIN/oscapd-cli && exit 1
$PYTHON $BIN/oscapd-cli --version || exit 1
$PYTHON $BIN/oscapd-cli -v || exit 1
$PYTHON $BIN/oscapd-cli --help || exit 1
$PYTHON $BIN/oscapd-cli -h || exit 1
