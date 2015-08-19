#!/usr/bin/env python
# Copyright (C) 2015 Brent Baude <bbaude@redhat.com>
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

'''
Functions used by the docker_scanner to
generate the results dict from the oscap results.xml files
'''


import xml.etree.ElementTree as ET
from collections import namedtuple
from image_scanner_client import Client
from scanner_error import ImageScannerClientError
import urlparse
import json


class Create_Summary(object):
    ''' Class that provides the functions '''

    _cve_tuple = namedtuple('oval_cve', ['title', 'severity', 'cve_ref_id',
                            'cve_ref_url', 'rhsa_ref_id', 'rhsa_ref_url',
                                         'cve', 'description'])

    def __init__(self):
        self.containers = None
        self.images = None
        self.cve_info = None

    def _get_root(self, result_file):
        '''
        Returns an ET object for the input XML which can be a file
        or a URL pointing to an xml file
        '''
        if result_file.startswith("http://"):
            split_url = urlparse.urlsplit(result_file)
            image_scanner = Client(split_url.hostname, port=split_url.port)
            result_tree = image_scanner.getxml(result_file)
        else:
            result_tree = ET.parse(result_file)
        return result_tree.getroot()

    def _get_list_cve_def_ids(self, _root):
        '''Returns a list of cve definition ids in the result file'''
        _def_id_list = []
        definitions = _root.findall("{http://oval.mitre.org/XMLSchema/"
                                    "oval-results-5}results/{http://oval.mitre"
                                    ".org/XMLSchema/oval-results-5}system/{"
                                    "http://oval.mitre.org/XMLSchema/oval-"
                                    "results-5}definitions/*[@result='true']")
        for def_id in definitions:
            _def_id_list.append(def_id.attrib['definition_id'])

        return _def_id_list

    def _get_cve_def_info(self, _def_id_list, _root):
        '''
        Returns a list of tuples that contain information about the
        cve themselves.  Currently return are: title, severity, ref_id
        and ref_url for the cve and rhsa, the cve id, and description
        '''

        cve_info_list = []
        for def_id in _def_id_list:
            oval_defs = _root.find("{http://oval.mitre.org/XMLSchema/oval-"
                                   "definitions-5}oval_definitions/{http://"
                                   "oval.mitre.org/XMLSchema/oval-definitions-"
                                   "5}definitions/*[@id='%s']/{http://oval."
                                   "mitre.org/XMLSchema/oval-definitions-5}"
                                   "metadata" % def_id)
            # title
            title = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval-"
                                   "definitions-5}title").text
            rhsa_meta = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval"
                                       "-definitions-5}reference[@source="
                                       "'RHSA']")
            cve_meta = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval-"
                                      "definitions-5}reference[@source='CVE']")
            # description
            description = oval_defs.find("{http://oval.mitre.org/XMLSchema/"
                                         "oval-definitions-5}description").text
            # severity
            severity = oval_defs.find("{http://oval.mitre.org/XMLSchema/oval-"
                                      "definitions-5}advisory/{http://oval."
                                      "mitre.org/XMLSchema/oval-definitions"
                                      "-5}severity").text
            cve_info_list.append(
                self._cve_tuple(title=title, severity=severity,
                                cve_ref_id=None if cve_meta is None
                                else cve_meta.attrib['ref_id'],
                                cve_ref_url=None if cve_meta is None
                                else cve_meta.attrib['ref_url'],
                                rhsa_ref_id=rhsa_meta.attrib['ref_id'],
                                rhsa_ref_url=rhsa_meta.attrib['ref_url'],
                                cve=def_id.replace(
                                    "oval:com.redhat.rhsa:def:", ""),
                                description=description))

        return cve_info_list

    def get_cve_info(self, result_file):
        '''
        Wrapper function to return a list of tuples with
        cve information from the xml input file
        '''
        _root = self._get_root(result_file)
        _id_list = self._get_list_cve_def_ids(_root)
        return self._get_cve_def_info(_id_list, _root)

    def _return_cve_dict_info(self, title):
        '''
        Returns a dict containing the specific details of a cve which
        includes title, rhsa/cve ref_ids and urls, cve number, and
        description.
        '''

        cve_tuple = [cved for cved in self.cve_info if cved.title == title][0]
        cve_dict_info = {'cve_title': cve_tuple.title,
                         'cve_ref_id': cve_tuple.cve_ref_id,
                         'cve_ref_url': cve_tuple.cve_ref_url,
                         'rhsa_ref_id': cve_tuple.rhsa_ref_id,
                         'rhsa_ref_url': cve_tuple.rhsa_ref_url,
                         'cve': cve_tuple.cve
                         }

        return cve_dict_info

    def _summarize_docker_object(self, result_file, docker_json, item_id):
        '''
        takes a result.xml file and a docker state json file and
        compares output to give an analysis of a given scan
        '''

        self.cve_info = self.get_cve_info(result_file)

        affected_image = 0
        affected_children = []
        is_image = self.is_id_an_image(item_id, docker_json)

        summary = {}
        if is_image:
            summary['scanned_image'] = item_id
            affected_image = item_id
            affected_children = self._process_image(affected_image,
                                                    docker_json)
        else:
            summary['scanned_container'] = item_id
            affected_children, affected_image = \
                self._process_container(docker_json, item_id)

        summary['image'] = affected_image
        summary['containers'] = affected_children

        scan_results = {}
        for cve in self.cve_info:
            _cve_specifics = self._return_cve_dict_info(cve.title)
            if cve.severity not in scan_results:
                scan_results[cve.severity] = \
                    {'num': 1,
                     'cves': [_cve_specifics]}
            else:
                scan_results[cve.severity]['num'] += 1
                scan_results[cve.severity]['cves'].append(_cve_specifics)
        summary['scan_results'] = scan_results
        # self.debug_json(summary)
        return summary

    def _process_container(self, docker_json, item_id):
        '''
        Returns containers with the same base image
        as a list
        '''
        affected_children = []
        for image_id in docker_json['docker_state']:
            for containers in docker_json['docker_state'][image_id]:
                if item_id == containers['uuid']:
                    base_image = image_id
        for containers in docker_json['docker_state'][base_image]:
            affected_children.append(containers['uuid'])

        return affected_children, base_image

    # Deprecate or rewrite
    def _process_image(self, affected_image, docker_json):
        '''
        Returns containers with a given base
        as a list
        '''
        affected_children = []
        # Catch an image that has no containers
        if affected_image not in docker_json['docker_state']:
            return []
        # It has children containers
        for containers in docker_json['docker_state'][affected_image]:
            affected_children.append(containers['uuid'])
        return affected_children

    def is_id_an_image(self, docker_id, docker_obj):
        '''
        helper function that uses the docker_state_file to validate if the
        given item_id is a container or image id
        '''

        if self.containers is None or self.images is None:
            self.containers = docker_obj['host_containers']
            self.images = docker_obj['host_images']

        if docker_id in self.images:
            return True
        elif docker_id in self.containers:
            return False
        else:
            # Item was not found in the docker state file
            error_msg = 'The provided openscap xml result file was ' \
                        'not generated from the same run as the ' \
                        'docker state file '
            raise ImageScannerClientError(error_msg)

    def debug_json(self, json_data):
        ''' Pretty prints a json object for debug purposes '''
        print json.dumps(json_data, indent=4, separators=(',', ': '))
