#!/bin/bash

# calls in this test should not require oscapd to be running
$PYTHON $BIN/oscapd-evaluate --help || exit 1
$PYTHON $BIN/oscapd-evaluate --h || exit 1
$PYTHON $BIN/oscapd-evaluate -v || exit 1
$PYTHON $BIN/oscapd-evaluate config || exit 1
$PYTHON $BIN/oscapd-evaluate --verbose config || exit 1
$PYTHON $BIN/oscapd-evaluate spec --input ../testing_data/ssg-fedora-ds.xml --print-xml || exit 1
$PYTHON $BIN/oscapd-evaluate spec --input ../testing_data/ssg-fedora-ds.xml --profile xccdf_org.ssgproject.content_profile_common --print-xml || exit 1


useradd testuser
out=$(su testuser -c "$PYTHON $BIN/oscapd 2>&1")
rv=$?
out2=$(su testuser -c "$PYTHON $BIN/oscapd-evaluate 2>&1")
rv2=$?
userdel -r testuser

[ $rv -ne 0 ] || exit 1
grep -iq "traceback" <<< "$out"
[ $? -ne 0 ] || exit 1

[ $rv2 -ne 0 ] || exit 1
grep -iq "traceback" <<< "$out2"
[ $? -ne 0 ] || exit 1
