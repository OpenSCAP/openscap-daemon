# Run OpenSCAP-daemon in SPC, use it on host

The daemon is containerized but has access to host resources. It can
scan other containers, container images or even machines.

## RHEL7 in SPC
Make sure the host machine is registered using 'subscription-manager'
before you start. Otherwise you won't be able to install packages
in the container.

```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-rhel7 rhel7_spc
atomic install openscap-daemon-rhel7
atomic run openscap-daemon-rhel7
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run 'oscapd-cli' or 'atomic scan' on the host
# and the SPC does the work
atomic stop openscap-daemon-rhel7
# you can stop the SPC with the 'atomic stop' command
```

## CentOS 7  in SPC
```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-centos7 centos7_spc
atomic install openscap-daemon-centos7
atomic run openscap-daemon-centos7
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run 'oscapd-cli' or 'atomic scan' on the host
# and the SPC does the work
atomic stop openscap-daemon-centos7
# you can stop the SPC with the 'atomic stop' command
```

## Fedora 24 in SPC
```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-f24 f24_spc
atomic install openscap-daemon-f24
atomic run openscap-daemon-f24
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run 'oscapd-cli' or 'atomic scan' on the host
# and the SPC does the work
atomic stop openscap-daemon-f24
# you can stop the SPC with the 'atomic stop' command
```

## Fedora 23 in SPC
```bash
cd openscap-daemon/atomic
docker build -t openscap-daemon-f23 f23_spc
atomic install openscap-daemon-f23
atomic run openscap-daemon-f23
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run 'oscapd-cli' or 'atomic scan' on the host
# and the SPC does the work
atomic stop openscap-daemon-f23
# you can stop the SPC with the 'atomic stop' command
```
