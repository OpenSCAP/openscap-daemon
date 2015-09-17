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


from openscap_daemon import dbus_daemon
from openscap_daemon.cve_scanner.scanner_error import ImageScannerClientError

import os
import dbus
import dbus.mainloop.glib
import json
import collections
import docker

# TODO: external dep!
from slip.dbus import polkit


class Client(object):
    ''' The image-scanner client API '''

    image_tmp = "/var/tmp/image-scanner"
    db_timeout = 99
    tup_names = ['number', 'workdir', 'logfile', 'nocache',
                 'reportdir']
    tup = collections.namedtuple('args', tup_names)

    def __init__(self, number=2,
                 logfile=os.path.join(image_tmp, "openscap.log"),
                 nocache=False,
                 reportdir=image_tmp, workdir=image_tmp):

        self.arg_tup = self.tup(number=number, logfile=logfile,
                                nocache=nocache, reportdir=reportdir,
                                workdir=workdir)

        self.arg_dict = {'number': number, 'logfile': logfile,
                         'nocache': nocache, 'reportdir': reportdir,
                         'workdir': workdir}
        self._docker_ping()
        self.num_threads = number
        self.bus = dbus.SessionBus()
        self.dbus_object = self.bus.get_object(dbus_daemon.BUS_NAME,
                                               dbus_daemon.OBJECT_PATH)
        self.logfile = logfile
        self.nocache = nocache
        self.reportdir = reportdir
        self.workdir = workdir
        self.onlyactive = False
        self.allcontainers = False
        self.allimages = False
        self.images = False

    @staticmethod
    def _docker_ping():
        d_conn = docker.Client()
        try:
            d_conn.ping()
        except Exception:
            raise ImageScannerClientError("The docker daemon does not appear"
                                          "to be running")

    @polkit.enable_proxy
    def inspect_container(self, cid):
        foo = self.dbus_object.inspect_container(
            cid,
            dbus_interface=dbus_daemon.DBUS_INTERFACE,
            timeout=self.db_timeout
        )
        return json.loads(foo)

    @polkit.enable_proxy
    def get_images_info(self):
        foo = self.dbus_object.images(
            dbus_interface=dbus_daemon.DBUS_INTERFACE,
            timeout=self.db_timeout
        )
        return json.loads(foo)

    @polkit.enable_proxy
    def get_containers_info(self):
        foo = self.dbus_object.containers(
            dbus_interface=dbus_daemon.DBUS_INTERFACE,
            timeout=self.db_timeout
        )
        return json.loads(foo)

    @polkit.enable_proxy
    def inspect_image(self, iid):
        foo = self.dbus_object.inspect_image(
            iid,
            dbus_interface=dbus_daemon.DBUS_INTERFACE,
            timeout=self.db_timeout
        )
        return json.loads(foo)

    def debug_json(self, json_data):
        ''' Debug function that pretty prints json objects'''
        print json.dumps(json_data, indent=4, separators=(',', ': '))

    @polkit.enable_proxy
    def scan_containers(self, only_active=False):
        if only_active:
            self.onlyactive = True
        else:
            self.allcontainers = True

        foo = self.dbus_object.scan_containers(
            self.onlyactive,
            self.allcontainers,
            self.num_threads,
            dbus_interface=dbus_daemon.DBUS_INTERFACE,
            timeout=self.db_timeout
        )
        return json.loads(foo)

    @polkit.enable_proxy
    def scan_images(self, all_images=False):
        if all_images:
            self.allimages = True
        else:
            self.images = True
        foo = self.dbus_object.scan_images(
            self.allimages, self.images,
            self.num_threads,
            dbus_interface=dbus_daemon.DBUS_INTERFACE,
            timeout=self.db_timeout
        )
        return json.loads(foo)

    @polkit.enable_proxy
    def scan_list(self, scan_list):
        if not isinstance(scan_list, list):
            raise ImageScannerClientError("Input to scan_list must be in"
                                          "the form of a list")
        return json.loads(
            self.dbus_object.scan_list(
                scan_list, self.num_threads,
                dbus_interface=dbus_daemon.DBUS_INTERFACE,
                timeout=self.db_timeout)
        )
