# based on Dockerfile by Brent Baude

FROM openscap-daemon-rhel7

RUN yum -y update && yum -y groupinstall "Development Tools" && yum -y install make wget git && yum clean all

RUN yum -y install scap-security-guide && yum clean all

RUN yum remove -y openscap openscap-utils && yum remove -y openscap-containers; \
    yum -y install autoconf automake libtool curl-devel libxml2-devel \
    libxslt-devel pcre-devel libacl-devel libselinux-devel libcap-devel \
    libblkid-devel bzip2-devel perl-XML-XPath bzip2 perl-XML-Parser swig \
    python-devel && yum clean all && \
    git clone -b maint-1.2 https://github.com/OpenSCAP/openscap.git && \
    pushd /openscap && ./autogen.sh && \
    ./configure --enable-sce --prefix=/usr && make -j 4 install && popd

# PYLINT=/bin/true skips pylint checks
RUN yum remove -y atomic; yum -y install python-setuptools dbus-python docker pygobject2 \
    python-docker-py libselinux-python python-requests && yum clean all && \
    git clone https://github.com/projectatomic/atomic.git && \
    pushd /atomic && PREFIX=/usr PYLINT=/bin/true GO_MD2MAN=/bin/true \
    make install && popd

RUN yum remove -y openscap-daemon; yum -y install python-setuptools dbus-python && yum clean all && \
    git clone https://github.com/OpenSCAP/openscap-daemon && \
    pushd /openscap-daemon && python setup.py install && popd
