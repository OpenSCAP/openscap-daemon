# based on Dockerfile by Brent Baude

FROM fedora:22

RUN dnf -y update && dnf -y groupinstall "Development Tools" && dnf -y install make git && dnf clean all

# TODO: Change to openscap package once 1.2.6 is everywhere
RUN dnf -y install autoconf automake libtool curl-devel libxml2-devel libxslt-devel pcre-devel libacl-devel libselinux-devel libcap-devel libblkid-devel bzip2-devel perl-XML-XPath bzip2 perl-XML-Parser swig python-devel && dnf clean all
RUN git clone -b maint-1.2 https://github.com/OpenSCAP/openscap.git && pushd /openscap && ./autogen.sh && ./configure --enable-sce --prefix=/usr && make -j 4 install && popd

# TODO: Change to Atomic package once 1.4 is everywhere
RUN dnf -y install dbus-python docker pygobject2 python-docker-py make pylint golang-github-cpuguy83-go-md2man python-psutil && dnf clean all
RUN git clone https://github.com/projectatomic/atomic.git && cd atomic && PREFIX=/usr PYLINT=/bin/true make install

# TODO: Don't clone from scratch, instead add local working copy there
RUN dnf -y install dbus-python && dnf clean all
RUN git clone https://github.com/OpenSCAP/openscap-daemon && pushd /openscap-daemon && python setup.py install && popd

ADD install.sh /root/

LABEL INSTALL="docker run -t --rm --privileged -v /:/host/ IMAGE sh /root/install.sh"

LABEL RUN="docker run -dt --privileged --pid=host -v /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup  -v /var/log:/var/log -v /run:/run -v /var/lib/docker/devicemapper/metadata/:/var/lib/docker/devicemapper/metadata/ -v /dev/:/dev/ -v /var/tmp/image-scanner:/var/tmp/image-scanner --env container=docker --net=host --cap-add=SYS_ADMIN --ipc=host IMAGE"

CMD oscapd
