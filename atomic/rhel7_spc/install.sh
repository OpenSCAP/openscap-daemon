set -x

ETC='/etc/oscapd'
ETC_FILE='config.ini'
HOST='/host'

echo "Adding the dbus configuration for the openscap-daemon to the host"
cp -v /etc/dbus-1/system.d/org.oscapd.conf /host/etc/dbus-1/system.d/


# Check if /etc/oscapd exists on the host
if [[ ! -d ${HOST}/${ETC} ]]; then
    mkdir ${HOST}/${ETC}
fi

DATE=$(date +'%Y-%m-%M-%T')

# Check if /etc/oscapd/config.ini exists
if [[ -f ${HOST}/${ETC}/${ETC_FILE} ]]; then
    SAVE_NAME=${ETC_FILE}.${DATE}.atomic_save
    echo "Saving current ${ETC_FILE} as ${SAVE_NAME}"
    mv ${HOST}/${ETC}/${ETC_FILE} ${HOST}/${ETC}/${SAVE_NAME}
fi

# Add config.ini to the host filesystem
echo "Updating ${ETC_FILE} with latest configuration"
cp ${ETC}/${ETC_FILE} ${HOST}/${ETC}

# Exit Message
echo "Installation complete. Be sure to customize ${ETC}/${ETC_FILE} as needed."
