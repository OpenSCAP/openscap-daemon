# OpenSCAP-daemon
This directory contains SPC containers with upstream version of packages.

To build images from this directory, you have to build stock image from [I'm a relative reference to a repository file](../atomic/).

## Fedora 23 in SPC
```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-f23 f23_spc

cd ../openscap-daemon/atomic-git
docker build -t openscap-daemon-f23-git f23_spc
# replace ID with the final ID that `docker build` gives you
atomic install $ID
atomic run $ID
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run oscapd-cli or atomic scan on the host
# and the SPC does the work
```
