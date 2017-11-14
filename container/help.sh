#!/bin/bash

DOCKER="/usr/bin/docker"
SELF=$1

VERSION=$(${DOCKER} inspect -f '{{ index .Config.Labels "version" }}' ${SELF})
RELEASE=$(${DOCKER} inspect -f '{{ index .Config.Labels "release" }}' ${SELF})
if [ -z ${RELEASE} ]; then
	echo -e "${SELF} image version: ${VERSION}\n"
else
	echo -e "${SELF} image version: ${VERSION}-${RELEASE}\n"
fi

DESCRIPTION=$(${DOCKER} inspect -f '{{ index .Config.Labels "description" }}' ${SELF})
echo -e "Description:\n${DESCRIPTION}\n"

echo "OpenSCAP packages bundled in ${SELF} image:"
rpm -qa | grep openscap
rpm -qa | grep scap-security-guide
