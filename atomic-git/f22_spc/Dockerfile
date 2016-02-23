# based on Dockerfile by Brent Baude

FROM openscap-daemon-f22

RUN dnf -y update && dnf -y groupinstall "Development Tools" && dnf -y install make wget git && dnf clean all

RUN dnf -y install 'dnf-command(builddep)' && dnf builddep -y atomic openscap-daemon openscap && dnf -y install libtool && dnf clean all

RUN git clone -b maint-1.2 https://github.com/OpenSCAP/openscap.git && \
    pushd /openscap && ./autogen.sh && \
    ./configure --enable-sce --prefix=/usr && make -j 4 install && popd

RUN git clone https://github.com/OpenSCAP/openscap-daemon && \
    pushd /openscap-daemon && python setup.py install && popd

RUN git clone https://github.com/projectatomic/atomic.git && \
    pushd /atomic && PREFIX=/usr PYLINT=/bin/true make install && \
    popd && rm -rf ./atomic
