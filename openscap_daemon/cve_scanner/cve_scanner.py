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

from openscap_daemon.cve_scanner.applicationconfiguration \
    import ApplicationConfiguration
from openscap_daemon.cve_scanner.reporter import Reporter
from openscap_daemon.cve_scanner.scan import Scan
from openscap_daemon.cve_scanner.generate_summary import Create_Summary
from openscap_daemon.cve_scanner.scanner_error import ImageScannerClientError
import dbus

from oscap_docker_python.get_cve_input import getInputCVE

import os
import timeit
import threading
import logging
import sys
import time
import signal
import subprocess
from datetime import datetime
import json
import platform
import collections


class ContainerSearch(object):
    ''' Does a series of docker queries to setup variables '''
    def __init__(self, appc):
        self.dead_cids = []
        self.ac = appc
        self.cons = self.ac.conn.containers(all=True)
        self.active_containers = self.ac.conn.containers(all=False)
        self.allimages = self.ac.conn.images(name=None, quiet=False,
                                             all=True, viz=False)
        self.images = self.ac.conn.images(name=None, quiet=False,
                                          all=False, viz=False)
        self.allimagelist = self._returnImageList(self.allimages)
        self.imagelist = self._returnImageList(self.images)
        self.fcons = self._formatCons(self.cons)
        self.fcons_active = self._formatCons(self.active_containers)
        self.ac.fcons = self.fcons
        self.ac.cons = self.cons
        self.ac.allimages = self.allimages
        self.ac.return_json = {}

    def _returnImageList(self, images):
        '''
        Walks through the image list and if the image
        size is not 0, it will add it to the returned
        list.
        '''

        il = []
        for i in images:
            if i['VirtualSize'] > 0:
                il.append(i['Id'])
        return il

    def _formatCons(self, cons):
        '''
        Returns a formatted dictionary of containers by
        image id like:

        fcons = {'iid': [{'cid': {'running': bool}}, ... ]}
        '''
        fcons = {}
        for c in cons:
            cid = c['Id']
            inspect = self.ac.conn.inspect_container(cid)
            iid = inspect['Image']
            run = inspect['State']['Running']
            if 'Dead' in inspect['State']:
                dead = inspect['State']['Dead']
            else:
                dead = False
            if dead:
                self.dead_cids.append(cid)
            if iid not in fcons:
                fcons[iid] = [{'uuid': cid, 'running': run, 'Dead': dead}]
            else:
                fcons[iid].append({'uuid': cid, 'running': run, 'Dead': dead})
        return fcons


class Worker(object):

    min_procs = 2
    max_procs = 4
    image_tmp = "/var/tmp/image-scanner"
    scan_args = ['allcontainers', 'allimages', 'images', 'logfile',
                 'fetch_cve', 'number', 'onlyactive', 'reportdir',
                 'workdir', 'url_root', 'host', 'rest_host',
                 'rest_port', 'scan', 'fetch_cve_url']

    scan_tuple = collections.namedtuple('Namespace', scan_args)

    def __init__(self, number=2,
                 logfile=os.path.join(image_tmp, "openscap.log"),
                 fetch_cve=False, reportdir=image_tmp, workdir=image_tmp,
                 host='unix://var/run/docker.sock',
                 allcontainers=False, onlyactive=False, allimages=False,
                 images=False, scan=[], fetch_cve_url=""):
        self.args =\
            self.scan_tuple(number=number, logfile=logfile,
                            fetch_cve=fetch_cve, reportdir=reportdir,
                            workdir=workdir, host=host,
                            allcontainers=allcontainers, allimages=allimages,
                            onlyactive=onlyactive, images=images, url_root='',
                            rest_host='', rest_port='', scan=scan,
                            fetch_cve_url=fetch_cve_url)

        self.ac = ApplicationConfiguration(parserargs=self.args)
        self.procs = self.set_procs(self.args.number)
        if not os.path.exists(self.ac.workdir):
            os.makedirs(self.ac.workdir)
        self.cs = ContainerSearch(self.ac)
        self.output = Reporter(self.ac)

        self.scan_list = None
        self.failed_scan = None
        self.rpms = {}

    def set_procs(self, number):
        if number is None:
            try:
                import multiprocessing
                numThreads = multiprocessing.cpu_count()

            except NotImplementedError:
                numThreads = 4
        else:
            numThreads = number

        if numThreads < self.min_procs:
            if self.ac.number is not None:
                print("The image-scanner requires --number to be a minimum " \
                      "of {0}. Setting --number to {1}".format(self.min_procs,
                                                               self.min_procs))
            return self.min_procs
        elif numThreads <= self.max_procs:
            return numThreads
        else:
            if self.ac.number is not None:
                print("Due to docker issues, we limit the max number "\
                      "of threads to {0}. Setting --number to "\
                      "{1}".format(self.max_procs, self.max_procs))
            return self.max_procs

    def _get_cids_for_image(self, cs, image):
        cids = []

        if image in cs.fcons:
            for container in cs.fcons[image]:
                cids.append(container['uuid'])
        else:
            for iid in cs.fcons:
                cids = [con['uuid'] for con in cs.fcons[iid]]
                if image in cids:
                    return cids

        return cids

    def return_active_threadnames(self, threads):
        thread_names = []
        for thread in threads:
            thread_name = thread._Thread__name
            if thread_name is not "MainThread":
                thread_names.append(thread_name)

        return thread_names

    def onlyactive(self):
        ''' This function sorts of out only the active containers'''
        con_list = []
        # Rid ourselves of 0 size containers
        for container in self.cs.active_containers:
            con_list.append(container['Id'])
        if len(con_list) == 0:
            error = "There are no active containers on this system"
            raise ImageScannerClientError(error)
        else:
            try:
                self._do_work(con_list)
            except Exception as error:
                raise ImageScannerClientError(str(error))

    def allimages(self):
        if len(self.cs.imagelist) == 0:
            error = "There are no images on this system"
            raise ImageScannerClientError(error)
        if self.args.allimages:
            try:
                self._do_work(self.cs.allimagelist)
            except Exception as error:
                raise ImageScannerClientError(str(error))
        else:
            try:
                self._do_work(self.cs.imagelist)
            except Exception as error:
                raise ImageScannerClientError(str(error))

    def list_of_images(self, image_list):
        try:
            self._do_work(image_list)
        except Exception as error:
            raise ImageScannerClientError(str(error))

    def allcontainers(self):
        if len(self.cs.cons) == 0:
            error = "There are no containers on this system"
            raise ImageScannerClientError(error)
        else:
            con_list = []
            for con in self.cs.cons:
                con_list.append(con['Id'])
            try:
                self._do_work(con_list)
            except Exception as error:
                raise ImageScannerClientError(str(error))

    def _do_work(self, image_list):
        self.scan_list = image_list
        cve_get = getInputCVE(self.image_tmp)
        if self.ac.fetch_cve_url != "":
            cve_get.url = self.ac.fetch_cve_url
        if self.ac.fetch_cve:
            cve_get.fetch_dist_data()
        threads = []

        for image in image_list:
            if image in self.cs.dead_cids:
                raise ImageScannerClientError("Scan not completed. Cannot "
                                              "scan the dead "
                                              "container {0}".format(image))
            cids = self._get_cids_for_image(self.cs, image)
            t = threading.Thread(target=self.search_containers, name=image,
                                 args=(image, cids, self.output,))
            threads.append(t)

        logging.info("Number of containers to scan: {0}".format(len(threads)))
        if isinstance(threading.current_thread(), threading._MainThread):
            signal.signal(signal.SIGINT, self.signal_handler)
        self.threads_complete = 0
        self.cur_scan_threads = 0
        while len(threads) > 0:
            if self.cur_scan_threads < self.procs:
                new_thread = threads.pop()
                new_thread.start()
                self.cur_scan_threads += 1

        while self.cur_scan_threads > 0:
            time.sleep(1)
            pass
        if self.failed_scan is not None:
            raise ImageScannerClientError(self.failed_scan)
        self.output.report_summary()

    def signal_handler(self, signal, frame):
        print("\n\nExiting...")
        sys.exit(0)

    def search_containers(self, image, cids, output):
        f = Scan(image, cids, output, self.ac)
        try:
            if f.get_release():

                t = timeit.Timer(f.scan).timeit(number=1)
                logging.debug("Scanned chroot for image {0}"
                              " completed in {1} seconds"
                              .format(image, t))
                try:
                    timeit.Timer(f.report_results).timeit(number=1)
                    image_rpms = f._get_rpms()
                    self.rpms[image] = image_rpms
                except Exception as error:
                    self.failed_scan = str(error)
            else:
                # This is not a RHEL image or container
                f._report_not_rhel(image)
        except subprocess.CalledProcessError:
            pass

        # umount and clean up temporary container
        f.DM.unmount_path(f.dest)
        f.DM._clean_temp_container_by_path(f.dest)

        self.threads_complete += 1
        self.cur_scan_threads -= 1

    def _check_input(self, image_list):
        '''
        Takes a list of image ids, image-names, container ids, or
        container-names and returns a list of images ids and
        container ids
        '''
        work_list = []

        # verify
        try:
            for image in image_list:
                iid = self.get_iid(image)
                work_list.append(iid)
        except ImageScannerClientError:
            error = "Unable to associate {0} with any image " \
                    "or container".format(image)
            raise ImageScannerClientError(error)
        return work_list

    def get_cid(self, input_name):
        """
        Given a container name or container id, it will return the
        container id
        """
        for container in self.ac.cons:
            if 'Names' in container and container['Names'] is not None:
                if (container['Id'].startswith(input_name)) or \
                        (('Names' in container) and
                         (any(input_name in item for item in
                              container['Names']))):
                    return container['Id']
                    break
        return None

    def _namesearch(self, input_name):
        """
        Looks to see if the input name is the name of a image
        """
        if ":" in input_name:
            image_name, tag = input_name.split(":")
        else:
            image_name = input_name
            tag = None

        name_search = self.ac.conn.images(name=image_name, all=True)
        # We found only one result, return it
        if len(name_search) == 1:
            return name_search[0]['Id']

        else:
            # We found multiple images with the input name
            # If a tag is passed, then we can return the right one
            # If not, we assume if all the image_ids are same, we
            # can use that.

            ilist = []
            for image in name_search:
                if input_name in image['RepoTags']:
                    return image['Id']
                else:
                    ilist.append(image['Id'])
            if tag is not None:
                raise ImageScannerClientError("Unable to find"
                                              "to an image named {0}"
                                              .format(input_name))
            # We didn't find it by name only. We check if the image_ids
            # are all the same
            if len(ilist) > 1:
                if all(ilist[0] == image for image in ilist) and (tag is None):
                    return ilist[0]
                else:
                    raise \
                        ImageScannerClientError("Found multiple images named"
                                                "{0} with different image Ids."
                                                "Try again with the image"
                                                "name and tag"
                                                .format(input_name))
        return None

    def get_iid(self, input_name):
        '''
        Find the image id based on a input_name which can be
        an image id, image name, or an image name:tag name.
        '''

        # Check if the input name is a container
        cid = self.get_cid(input_name)

        if cid is not None:
            return cid

        # Check if the input_name was an image name or name:tag
        image_id = self._namesearch(input_name)
        if image_id is not None:
            return image_id

        # Maybe input name is an image id (or portion)
        for image in self.ac.allimages:
            if image['Id'].startswith(input_name):
                return image['Id']

        raise ImageScannerClientError("Unable to associate {0} with any image"
                                      .format(input_name))

    def start_application(self):
        if not self.args.onlyactive and not self.args.allcontainers and \
                not self.allimages and not self.args.images and \
                not self.args.scan:
            return {'Error': 'No scan type was selected'}

        start_time = time.time()
        logging.basicConfig(filename=self.ac.logfile,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M', level=logging.DEBUG)
        if self.args.onlyactive:
            self.onlyactive()
        elif self.args.allcontainers:
            self.allcontainers()
        elif self.args.allimages or self.args.images:
            self.allimages()
        else:
            # Check to make sure we have valid input
            image_list = self._check_input(self.args.scan)

            try:
                self.list_of_images(image_list)
            except ImageScannerClientError as error:
                raise dbus.exceptions.DBusException(str(error))

        end_time = time.time()
        duration = (end_time - start_time)
        if duration < 60:
            unit = "seconds"
        else:
            unit = "minutes"
            duration = duration / 60
        logging.info("Completed entire scan in {0} {1}".format(duration, unit))
        docker_state = self.dump_json_log()
        return docker_state

    def _get_rpms_by_obj(self, docker_obj):
        return self.rpms[docker_obj]

    def dump_json_log(self):
        '''
        Creates a log of information about the scan and what was
        scanned for post-scan analysis
        '''
        xmlp = Create_Summary()

        # Common Information
        json_log = {}
        json_log['hostname'] = platform.node()
        json_log['scan_time'] = datetime.today().isoformat(' ')
        json_log['scanned_content'] = self.scan_list
        json_log['host_results'] = {}
        json_log['docker_state'] = self.ac.fcons
        json_log['host_images'] = [image['Id'] for image in self.ac.allimages]
        json_log['host_containers'] = [con['Id'] for con in self.ac.cons]
        json_log['docker_state_url'] = self.ac.json_url

        tuple_keys = ['rest_host', 'rest_port', 'allcontainers',
                      'allimages', 'images', 'logfile', 'number',
                      'reportdir', 'workdir', 'url_root',
                      'host', 'fetch_cve_url']
        for tuple_key in tuple_keys:
            tuple_val = None if not hasattr(self.ac.parserargs, tuple_key) \
                else getattr(self.ac.parserargs, tuple_key)
            json_log[tuple_key] = tuple_val

        # Per scanned obj information

        for docker_obj in self.scan_list:
            json_log['host_results'][docker_obj] = {}
            tmp_obj = json_log['host_results'][docker_obj]
            if 'msg' in self.ac.return_json[docker_obj].keys():
                tmp_obj['isRHEL'] = False
            else:
                tmp_obj['rpms'] = self._get_rpms_by_obj(docker_obj)
                tmp_obj['isRHEL'] = True
                xml_path = self.ac.return_json[docker_obj]['xml_path']
                tmp_obj['cve_summary'] = \
                    xmlp._summarize_docker_object(xml_path,
                                                  json_log, docker_obj)

        # Pulling out good stuff from summary by docker object
        for docker_obj in self.ac.return_json.keys():
            if 'msg' not in self.ac.return_json[docker_obj].keys():
                for key, value in self.ac.return_json[docker_obj].iteritems():
                    json_log['host_results'][docker_obj][key] = value

        json_log['results_summary'] = self.ac.return_json

        # DEBUG
        # print(json.dumps(json_log, indent=4, separators=(',', ': ')))
        with open(self.ac.docker_state, 'w') as state_file:
            json.dump(json_log, state_file)

        return json_log
