# Run OpenSCAP-daemon in SPC, use it on host

The daemon is containerized but has access to host resources. It can
scan other containers, container images or even machines.

## Fedora 22 in SPC
```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-f22 f22_spc
# replace ID with the final ID that `docker build` gives you
atomic install $ID
atomic run $ID
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run oscapd-cli or atomic scan on the host
# and the SPC does the work
```

## Fedora 23 in SPC
You can build Fedora 23 based SPC in the same way as Fedora 22 based.
```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-f23 f23_spc
# replace ID with the final ID that `docker build` gives you
atomic install $ID
atomic run $ID
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run oscapd-cli or atomic scan on the host
# and the SPC does the work
```

## RHEL7 in SPC
Make sure the host machine is registered using subscription-manager
before you start. Otherwise you won't be able to install packages
in the container.

```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-rhel7 rhel7_spc
# replace ID with the final ID that `docker build` gives you
atomic install $ID
atomic run $ID
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run oscapd-cli or atomic scan on the host
# and the SPC does the work
```
