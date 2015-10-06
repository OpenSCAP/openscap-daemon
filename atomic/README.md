# use-case 1: Run OpenSCAP-daemon in SPC, use it on host

```bash
cd openscap-daemon/atomic
docker build f22
# replace ID with the final ID that `docker build` gives you
atomic run $ID
# at this point OpenSCAP Daemon dbus API is provided on the host
# that means that you can run oscapd-cli or atomic scan on the host
# and the SPC does the work
```
