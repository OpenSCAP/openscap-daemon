#!/bin/bash

DOCKERFILE="/root/Dockerfile"

VERSION=$(grep ' version=' $DOCKERFILE | sed 's|.*version="\(.*\)".*|\1|')
RELEASE=$(grep ' release=' $DOCKERFILE | sed 's|.*release="\(.*\)".*|\1|')
if [ -z ${RELEASE} ]; then
	echo -e "Image version: ${VERSION}\n"
else
	echo -e "Image version: ${VERSION}-${RELEASE}\n"
fi

DESCRIPTION=$(grep ' description=' $DOCKERFILE \
	| sed 's|.*description="\(.*\)".*|\1|')
echo -e "Description:\n${DESCRIPTION}\n"

echo "OpenSCAP packages bundled in the image:"
rpm -qa | grep openscap
rpm -qa | grep scap-security-guide
