# based on Dockerfile by Brent Baude

FROM rhel7

RUN yum -y update && \
    yum-config-manager --enable rhel-7-server-optional-rpms rhel-7-server-extras-rpms && \
    yum -y install atomic && \
    yum clean all

RUN cd /etc/yum.repos.d/ ; curl -O https://copr.fedorainfracloud.org/coprs/isimluk/OpenSCAP/repo/epel-7/isimluk-OpenSCAP-epel-7.repo && \
    yum -y install openscap-containers scap-security-guide && \
    yum clean all

RUN rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    yum -y install openscap-daemon && \
    yum clean all

RUN yum -y install wget && \
    yum clean all

ADD install.sh /root/

LABEL INSTALL="docker run --rm --privileged -v /:/host/ IMAGE sh /root/install.sh"

LABEL RUN="docker run -d --privileged --pid=host -v /etc/oscapd:/etc/oscapd -v /proc/:/hostproc/ -v /sys/fs/cgroup:/sys/fs/cgroup  -v /var/log:/var/log -v /run:/run -v /var/lib/docker/devicemapper/metadata/:/var/lib/docker/devicemapper/metadata/ -v /dev/:/dev/ -v /var/tmp/image-scanner:/var/tmp/image-scanner --env container=docker --net=host --cap-add=SYS_ADMIN --ipc=host IMAGE"

# Dockerfile reference discourages "ADD" with remote source
# I would love to tag this with NOCACHE but Dockerfile doesn't have an
# instruction for that. Instead the person building it has to use --no-cache
RUN wget --no-verbose -P /var/tmp/image-scanner/ \
    https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL{5,6,7}.xml.bz2

CMD oscapd
