#!/bin/bash

ETC='/etc/oscapd'
ETC_FILE='config.ini'
HOST='/host'
SELF=$1

echo ""
echo "Installing the configuration file 'openscap' into /etc/atomic.d/.  You can now use this scanner with atomic scan with the --scanner openscap command-line option.  You can also set 'openscap' as the default scanner in /etc/atomic.conf.  To list the scanners you have configured for your system, use 'atomic scan --list'."

echo ""
cp /root/openscap /host/etc/atomic.d/
sed -i "s|\$IMAGE_NAME|${SELF}|" /host/etc/atomic.d/openscap

SCRIPTS="/etc/atomic.d/scripts/"
echo ""
echo "Copying the remediation script 'remediate.py' into $SCRIPTS. You can now remediate images with atomic scan using --remediate command-line option."
echo ""
if [[ ! -d $HOST/$SCRIPTS ]]; then
	mkdir -p $HOST/$SCRIPTS
fi
cp /root/remediate.py $HOST/$SCRIPTS


# Check if /etc/oscapd exists on the host
if [[ ! -d ${HOST}/${ETC} ]]; then
    mkdir ${HOST}/${ETC}
fi

DATE=$(date +'%Y-%m-%d-%T')

# Check if /etc/oscapd/config.ini exists
if [[ -f ${HOST}/${ETC}/${ETC_FILE} ]]; then
    SAVE_NAME=${ETC_FILE}.${DATE}.atomic_save
    echo "Saving current ${ETC_FILE} as ${SAVE_NAME}"
    mv ${HOST}/${ETC}/${ETC_FILE} ${HOST}/${ETC}/${SAVE_NAME}
fi

# Add config.ini to the host filesystem
echo "Updating ${ETC_FILE} with latest configuration"
cp /root/config.ini ${HOST}/${ETC}/

# Exit Message
echo "Installation complete. You can customize ${ETC}/${ETC_FILE} as needed."


echo ""
