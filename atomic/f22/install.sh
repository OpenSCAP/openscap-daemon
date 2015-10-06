set -x

echo "Adding the dbus configuration for the openscap-daemon to the host"

cp -v /etc/dbus-1/system.d/org.openscapd.conf /host/etc/dbus-1/system.d/

