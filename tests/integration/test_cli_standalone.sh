#!/bin/bash

# calls in this test should not require oscapd to be running

set -e

$PYTHON $BIN/oscapd-cli --version
$PYTHON $BIN/oscapd-cli -v
