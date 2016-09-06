# based on Dockerfile by Brent Baude

FROM fedora:24

ENV container docker

RUN dnf -y install \
                atomic \
                openscap-containers \
                openscap-daemon \
                scap-security-guide \
                wget && \
    dnf clean all

ADD install.sh /root/

ADD config.ini /etc/oscapd/

LABEL INSTALL="docker run --rm --privileged -v /:/host/ IMAGE sh /root/install.sh"

LABEL RUN="docker run -d --privileged --pid=host -v /etc/oscapd:/etc/oscapd -v /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup  -v /var/log:/var/log -v /run:/run -v /var/lib/docker/devicemapper/metadata/:/var/lib/docker/devicemapper/metadata/ -v /dev/:/dev/ -v /var/tmp/image-scanner:/var/tmp/image-scanner --net=host --cap-add=SYS_ADMIN --ipc=host --name NAME IMAGE"

LABEL STOP="docker kill -s INT \${NAME}"

# Dockerfile reference discourages "ADD" with remote source
# I would love to tag this with NOCACHE but Dockerfile doesn't have an
# instruction for that. Instead the person building it has to use --no-cache
RUN wget --no-verbose -P /var/tmp/image-scanner/ \
    https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL{5,6,7}.xml.bz2

CMD ["/usr/bin/oscapd"]
