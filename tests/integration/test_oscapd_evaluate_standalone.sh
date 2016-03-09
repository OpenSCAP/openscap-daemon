#!/bin/bash

# calls in this test should not require oscapd to be running

$PYTHON $BIN/oscapd-evaluate spec --input ../testing_data/ssg-fedora-ds.xml --print-xml || exit 1
$PYTHON $BIN/oscapd-evaluate spec --input ../testing_data/ssg-fedora-ds.xml --profile xccdf_org.ssgproject.content_profile_common --print-xml || exit 1
