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

'''Reporter Class'''

import collections
import os


class Reporter(object):
    ''' Does stdout reporting '''
    def __init__(self, appc):
        self.output = collections.namedtuple('Summary', 'iid, cid, os, sevs,'
                                             'log, msg',)
        self.list_of_outputs = []
        self.appc = appc
        self.report_dir = os.path.join(self.appc.reportdir, "reports")
        self.appc.docker_state = os.path.join(self.report_dir,
                                              "docker_state.json")

        if not os.path.exists(self.report_dir):
            os.mkdir(self.report_dir)
        self.content = ""

    def report_summary(self):
        '''
        This function is the primary function to output results
        to stdout when running the image-scanner
        '''
        for image in self.list_of_outputs:
            short_cid_list = []
            image_json = {image.iid: {}}
            image_json[image.iid]['xml_path'] = os.path.join(
                self.report_dir, image.iid + ".xml")
            if image.msg is None:
                for cid in image.cid:
                    short_cid_list.append(cid[:12])
                image_json[image.iid]['cids'] = short_cid_list
                image_json[image.iid]['critical'] = image.sevs['Critical']
                image_json[image.iid]['important'] = \
                    image.sevs['Important']
                image_json[image.iid]['moderate'] = image.sevs['Moderate']
                image_json[image.iid]['low'] = image.sevs['Low']
                image_json[image.iid]['os'] = image.os
            else:
                image_json[image.iid]['msg'] = image.msg
            self.appc.return_json[image.iid] = image_json[image.iid]
        report_files = []
        for image in self.list_of_outputs:
            if image.msg is None:
                short_image = image.iid[:12] + ".scap"
                out = open(os.path.join(self.report_dir, short_image), 'w')
                report_files.append(short_image)
                out.write(image.log)
                out.close()
        for report in report_files:
            os.path.join(self.report_dir, report)

    def _get_dtype(self, iid):
        ''' Returns whether the given id is an image or container '''
        # Images
        for image in self.appc.allimages:
            if image['Id'].startswith(iid):
                return "Image"
        # Containers
        for con in self.appc.cons:
            if con['Id'].startswith(iid):
                return "Container"
        return None
