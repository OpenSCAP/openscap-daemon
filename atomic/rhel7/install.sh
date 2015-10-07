set -x

echo "Adding the dbus configuration for the openscap-daemon to the host"
cp -v /etc/dbus-1/system.d/org.oscapd.conf /host/etc/dbus-1/system.d/
