# Copyright (C) 2015 Brent Baude <bbaude@redhat.com>
# Copyright (C) 2015 Red Hat Inc., Durham, North Carolina.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

import os
import collections
import time
import logging
import subprocess
import xml.etree.ElementTree as ET
import platform
import StringIO
from Atomic.mount import DockerMount
from openscap_daemon.cve_scanner.scanner_error import ImageScannerClientError
from oscap_docker_python.get_cve_input import getInputCVE
import bz2

# TODO: External dep!
import rpm


class Scan(object):
    def __init__(self, image_uuid, con_uuids, output, appc):
        self.image_name = image_uuid
        self.ac = appc
        self.CVEs = collections.namedtuple('CVEs', 'title, severity,'
                                           'cve_ref_id, cve_ref_url,'
                                           'rhsa_ref_id, rhsa_ref_url')

        self.list_of_CVEs = []
        self.con_uuids = con_uuids
        self.output = output
        self.report_dir = os.path.join(self.ac.workdir, "reports")
        if not os.path.exists(self.report_dir):
            os.mkdir(self.report_dir)

        start = time.time()
        self.DM = DockerMount("/tmp", mnt_mkdir=True)
        self.dm_results = self.DM.mount(image_uuid)
        logging.debug("Created scanning chroot in {0}"
                      " seconds".format(time.time() - start))
        self.dest = self.dm_results

    def get_release(self):
        etc_release_path = os.path.join(self.dest, "rootfs",
                                        "etc/redhat-release")

        if not os.path.exists(etc_release_path):
            logging.info("{0} is not RHEL based".format(self.image_name))
            return False

        self.os_release = open(etc_release_path).read()
        self.ac.os_release = self.os_release

        rhel = 'Red Hat Enterprise Linux'

        if rhel in self.os_release:
            logging.debug("{0} is {1}".format(self.image_name,
                                              self.os_release.rstrip()))
            return True
        else:
            logging.info("{0} is {1}".format(self.image_name,
                                             self.os_release.rstrip()))
            return False

    def scan(self):
        logging.debug("Scanning chroot {0}".format(self.image_name))
        hostname = open("/etc/hostname").read().rstrip()
        os.environ["OSCAP_PROBE_ARCHITECTURE"] = platform.processor()
        os.environ["OSCAP_PROBE_ROOT"] = os.path.join(self.dest, "rootfs")
        os.environ["OSCAP_PROBE_OS_NAME"] = platform.system()
        os.environ["OSCAP_PROBE_OS_VERSION"] = platform.release()
        os.environ["OSCAP_PROBE_"
                   "PRIMARY_HOST_NAME"] = "{0}:{1}".format(hostname,
                                                           self.image_name)

        # We only support RHEL 6|7 in containers right now
        osc = getInputCVE("/tmp")
        if "Red Hat Enterprise Linux" in self.os_release:
            if "7." in self.os_release:
                self.chroot_cve_file = os.path.join(
                    self.ac.workdir, osc.dist_cve_name.format("7"))
            if "6." in self.os_release:
                self.chroot_cve_file = os.path.join(
                    self.ac.workdir, osc.dist_cve_name.format("6"))
        cmd = ['oscap', 'oval', 'eval', '--report',
               os.path.join(self.report_dir,
                            self.image_name + '.html'),
               '--results',
               os.path.join(self.report_dir,
                            self.image_name + '.xml'), self.chroot_cve_file]

        logging.debug(
            "Starting evaluation with command '%s'.",
        " ".join(cmd))

        try:
            self.result = subprocess.check_output(cmd)
        except Exception:
            pass
    # def capture_run(self, cmd):
    #     '''
    #     Subprocess command that captures and returns the output and
    #     return code.
    #     '''

    #     r = subprocess.Popen(cmd, stdout=subprocess.PIPE,
    #                          stderr=subprocess.PIPE)
    #     return r.communicate(), r.returncode

    def get_cons(self, fcons, short_iid):
        cons = []
        for image in fcons:
            if image.startswith(short_iid):
                for con in fcons[image]:
                    cons.append(con['uuid'][:12])
        return cons

    def report_results(self):
        if not os.path.exists(self.chroot_cve_file):
            raise ImageScannerClientError("Unable to find {0}"
                                          .format(self.chroot_cve_file))
            return False
        cve_tree = ET.parse(bz2.BZ2File(self.chroot_cve_file))
        self.cve_root = cve_tree.getroot()

        for line in self.result.splitlines():
            split_line = line.split(':')
            # Not in love with how I did this
            # Should find a better marked to know if it is a line
            # a parsable line.
            if (len(split_line) == 5) and ('true' in split_line[4]):
                self._return_xml_values(line.split()[1][:-1])

        sev_dict = {}
        sum_log = StringIO.StringIO()
        sum_log.write("Image: {0} ({1})".format(self.image_name,
                                                self.os_release))
        cons = self.get_cons(self.ac.fcons, self.image_name)
        sum_log.write("\nContainers based on this image ({0}): {1}\n"
                      .format(len(cons), ", ".join(cons)))
        for sev in ['Critical', 'Important', 'Moderate', 'Low']:
            sev_counter = 0
            for cve in self.list_of_CVEs:
                if cve.severity == sev:
                    sev_counter += 1
                    sum_log.write("\n")
                    fields = list(self.CVEs._fields)
                    fields.remove('title')
                    sum_log.write("{0}{1}: {2}\n"
                                  .format(" " * 5, "Title",
                                          getattr(cve, "title")))

                    for field in fields:
                        sum_log.write("{0}{1}: {2}\n"
                                      .format(" " * 10, field.title(),
                                              getattr(cve, field)))
            sev_dict[sev] = sev_counter
        self.output.list_of_outputs.append(
            self.output.output(iid=self.image_name, cid=self.con_uuids,
                               os=self.os_release, sevs=sev_dict,
                               log=sum_log.getvalue(), msg=None))
        sum_log.close()

    def _report_not_rhel(self, image):
        msg = "{0} is not based on RHEL".format(image[:8])
        self.output.list_of_outputs.append(
            self.output.output(iid=image, cid=None,
                               os=None, sevs=None,
                               log=None, msg=msg))

    def _return_xml_values(self, cve):
        cve_string = ("{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
                      "definitions/*[@id='%s']" % cve)
        cve_xml = self.cve_root.find(cve_string)
        title = cve_xml.find("{http://oval.mitre.org/XMLSchema/oval-"
                             "definitions-5}metadata/"
                             "{http://oval.mitre.org/XMLSchema/"
                             "oval-definitions-5}title")
        cve_id = cve_xml.find("{http://oval.mitre.org/XMLSchema/"
                              "oval-definitions-5}metadata/{http://oval.mitre."
                              "org/XMLSchema/oval-definitions-5}reference"
                              "[@source='CVE']")
        sev = (cve_xml.find("{http://oval.mitre.org/XMLSchema/oval-definitions"
                            "-5}metadata/{http://oval.mitre.org/XMLSchema/oval"
                            "-definitions-5}advisory/")).text

        if cve_id is not None:
            cve_ref_id = cve_id.attrib['ref_id']
            cve_ref_url = cve_id.attrib['ref_url']
        else:
            cve_ref_id = None
            cve_ref_url = None

        rhsa_id = cve_xml.find("{http://oval.mitre.org/XMLSchema/oval-"
                               "definitions-5}metadata/{http://oval.mitre.org"
                               "/XMLSchema/oval-definitions-5}reference"
                               "[@source='RHSA']")

        if rhsa_id is not None:
            rhsa_ref_id = rhsa_id.attrib['ref_id']
            rhsa_ref_url = rhsa_id.attrib['ref_url']
        else:
            rhsa_ref_id = None
            rhsa_ref_url = None

        self.list_of_CVEs.append(
            self.CVEs(title=title.text, cve_ref_id=cve_ref_id,
                      cve_ref_url=cve_ref_url, rhsa_ref_id=rhsa_ref_id,
                      rhsa_ref_url=rhsa_ref_url, severity=sev))

    def _get_rpms(self):
        chroot_os = os.path.join(self.dest, "rootfs")
        ts = rpm.TransactionSet(chroot_os)
        ts.setVSFlags((rpm._RPMVSF_NOSIGNATURES | rpm._RPMVSF_NODIGESTS))
        image_rpms = []
        for hdr in ts.dbMatch():  # No sorting
            if hdr['name'] == 'gpg-pubkey':
                continue
            else:
                foo = "{0}-{1}-{2}-{3}-{4}".format(hdr['name'],
                                                   hdr['epochnum'],
                                                   hdr['version'],
                                                   hdr['release'],
                                                   hdr['arch'])
                image_rpms.append(foo)
        return image_rpms
