# based on Dockerfile by Brent Baude

FROM fedora:23

RUN dnf -y install openscap-scanner openscap-utils openscap-containers scap-security-guide && dnf clean all
RUN dnf -y install atomic && dnf clean all

# TODO: Don't clone from scratch, instead add local working copy there
RUN dnf -y install git python3 python3-devel python3-gobject-base \
    python3-setuptools dbus python3-dbus python-requests && dnf clean all && \
    git clone https://github.com/OpenSCAP/openscap-daemon && \
    pushd /openscap-daemon && python3 setup.py install && popd

ADD install.sh /root/

LABEL INSTALL="docker run -t --rm --privileged -v /:/host/ IMAGE sh /root/install.sh"

LABEL RUN="docker run -dt --privileged --pid=host -v /etc/oscapd:/etc/oscapd -v /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup  -v /var/log:/var/log -v /run:/run -v /var/lib/docker/devicemapper/metadata/:/var/lib/docker/devicemapper/metadata/ -v /dev/:/dev/ -v /var/tmp/image-scanner:/var/tmp/image-scanner --env container=docker --net=host --cap-add=SYS_ADMIN --ipc=host IMAGE"

RUN dnf -y install wget && dnf clean all

# Dockerfile reference discourages "ADD" with remote source
# I would love to tag this with NOCACHE but Dockerfile doesn't have an
# instruction for that. Instead the person building it has to use --no-cache
RUN wget --no-verbose -P /var/tmp/image-scanner/ \
    https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL{5,6,7}.xml.bz2

CMD oscapd
