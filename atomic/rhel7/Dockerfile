# based on Dockerfile by Brent Baude

FROM rhel7

RUN yum -y update && yum -y groupinstall "Development Tools" && yum -y install make git && yum clean all

RUN yum -y install scap-security-guide && yum clean all

# TODO: Change to openscap package once 1.2.6 is everywhere
RUN yum -y install autoconf automake libtool curl-devel libxml2-devel \
    libxslt-devel pcre-devel libacl-devel libselinux-devel libcap-devel \
    libblkid-devel bzip2-devel perl-XML-XPath bzip2 perl-XML-Parser swig \
    python-devel && yum clean all && \
    git clone -b maint-1.2 https://github.com/OpenSCAP/openscap.git && \
    pushd /openscap && ./autogen.sh && \
    ./configure --enable-sce --prefix=/usr && make -j 4 install && popd

# TODO: Change to Atomic package once 1.4 is everywhere
# PYLINT=/bin/true skips pylint checks
RUN yum -y install python-setuptools dbus-python docker pygobject2 \
    python-docker-py libselinux-python && yum clean all && \
    git clone -b go_md2man_configurable https://github.com/mpreisler/atomic.git && \
    pushd /atomic && PREFIX=/usr PYLINT=/bin/true GO_MD2MAN=/bin/true \
    make install && popd

# TODO: Don't clone from scratch, instead add local working copy there
RUN yum -y install python-setuptools dbus-python && yum clean all && \
    git clone https://github.com/OpenSCAP/openscap-daemon && \
    pushd /openscap-daemon && python setup.py install && popd

ADD install.sh /root/

LABEL INSTALL="docker run -t --rm --privileged -v /:/host/ IMAGE sh /root/install.sh"

LABEL RUN="docker run -dt --privileged --pid=host -v /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup  -v /var/log:/var/log -v /run:/run -v /var/lib/docker/devicemapper/metadata/:/var/lib/docker/devicemapper/metadata/ -v /dev/:/dev/ -v /var/tmp/image-scanner:/var/tmp/image-scanner --env container=docker --net=host --cap-add=SYS_ADMIN --ipc=host IMAGE"

CMD oscapd
