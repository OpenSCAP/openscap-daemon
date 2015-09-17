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


''' Image scanner API '''

import requests
import urlparse
import json
import xml.etree.ElementTree as ET
import ConfigParser
import collections
import os
from multiprocessing.dummy import Pool as ThreadPool


class ImageScannerClientError(Exception):
    """Docker Error"""
    pass


class Client(requests.Session):
    ''' The image-scanner client API '''

    request_headers = {'content-type': 'application/json'}

    def __init__(self, host, port=5001, number=2):
        '''
        When instantiating, pass in the host and optionally
        the port and threading counts
        '''
        super(Client, self).__init__()
        self.host = "http://{0}:{1}" .format(host, port)
        self.api_path = "image-scanner/api"
        self.num_threads = number
        self.client_common = ClientCommon()

    def scan_all_containers(self, onlyactive=False):
        ''' Scans all containers and returns results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/scan")
        con_scan = 'allcontainers' if onlyactive is False else 'onlyactive'
        params = {con_scan: True, 'number': self.num_threads}
        results = self._get_results(url, data=json.dumps(params))
        self._check_result(results)
        return json.loads(results.text)

    def scan_list(self, scan_list):
        '''
        Scans a list of containers/images by name or id and returns
        results in json
        '''
        if not isinstance(scan_list, list):
            raise ImageScannerClientError("You must pass input in list form")
        url = urlparse.urljoin(self.host, self.api_path + "/scan")
        params = {'scan': scan_list, 'number': self.num_threads}
        results = self._get_results(url, data=json.dumps(params))
        self._check_result(results)
        return json.loads(results.text)

    def scan_images(self, all=False):
        '''Scans all images and returns results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/scan")
        if all:
            params = {'allimages': True, 'number': self.num_threads}
        else:
            params = {'images': True, 'number': self.num_threads}
        results = self._get_results(url, data=json.dumps(params))
        self._check_result(results)
        return json.loads(results.text)

    def inspect_container(self, cid):
        '''Inspects a container and returns all results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/inspect_container")
        results = self._get_results(url, data=json.dumps({'cid': cid}))
        return json.loads(results.text)

    def inspect_image(self, iid):
        '''Inspects a container and returns the results in json'''
        url = urlparse.urljoin(self.host, self.api_path + "/inspect_image")
        results = self._get_results(url, json.dumps({'iid': iid}))
        return json.loads(results.text)

    def getxml(self, url):
        '''
        Given a URL string, returns the results of an openscap XML file as
        an Element Tree
        '''
        try:
            results = self.get(url)
        except requests.exceptions.ConnectionError:
            raise ImageScannerClientError("Unable to connect to REST server "
                                          "at {0}".format(url))
        return ET.ElementTree(ET.fromstring(results.content))

    def get_docker_json(self, url):
        '''
        Given a URL, return the state of the docker containers and images
        when the images-scanning occurred.  Returns as JSON object.
        '''
        try:
            results = self.get(url)
        except requests.exceptions.ConnectionError:
            raise ImageScannerClientError("Unable to connect to REST server "
                                          "at {0}".format(url))
        return json.loads(results.text)

    def _get_results(self, url, data=None, headers=None):
        '''Wrapper functoin for calling the request.session.get'''
        headers = self.request_headers if headers is None else headers
        try:
            if data is not None:
                results = self.get(url, data=data,
                                   headers=headers)
            else:
                results = self.get(url, headers=headers, timeout=9)
        except requests.exceptions.ConnectionError:
            raise ImageScannerClientError("Unable to connect to REST server "
                                          "at {0}".format(url))
        except requests.exceptions.Timeout:
            raise ImageScannerClientError("Timeout reached with REST server "
                                          "at {0}".format(url))

        return results

    @staticmethod
    def _check_result(result):
        '''
        Examines a json object looking for a key of 'Error'
        which indicates the previous call did not work.  Raises
        an exception upon finding the key
        '''
        result_json = json.loads(result.text)
        if 'Error' in result_json:
            raise ImageScannerClientError(result_json['Error'])

        if 'results' in result_json.keys() and 'Error' \
                in result_json['results']:
            raise ImageScannerClientError(result_json['results']['Error'])

    def ping(self):
        '''
        Throws an exception if it cannot access the REST server or
        the docker host
        '''
        url = urlparse.urljoin(self.host, self.api_path + "/ping")
        results = self._get_results(url)
        if 'results' not in json.loads(results.text):
            tmp_obj = json.loads(results.text)
            if hasattr(tmp_obj, 'error'):
                error = getattr(tmp_obj, 'error')
            else:
                error = tmp_obj['Error']

            error = error.replace('on the host ', 'on the host {0} '
                                  .format(self.host))
            raise ImageScannerClientError(error)


class ClientCommon(object):
    ''' Clients functions that are shared with other classes '''

    config_file = "/etc/image-scanner/image-scanner-client.conf"
    profile_tuple = collections.namedtuple('profiles', ['profile',
                                                        'host',
                                                        'port',
                                                        'cert',
                                                        'number'])
    args_tuple = collections.namedtuple('scan_args',
                                        ['allimages', 'images',
                                         'allcontainers', 'onlyactive'])

    client_dir = "/var/tmp/image-scanner/client"

    if not os.path.exists(client_dir):
        os.makedirs(client_dir)

    uber_file_path = os.path.join(client_dir, 'uber_docker.json')

    def __init__(self):
        self.uber_docker = {}
        self.num_complete = 0
        self.num_total = 0
        self.last_completed = ""
        self.threads = 0

    @staticmethod
    def debug_json(json_data):
        ''' Debug function that pretty prints json objects'''
        print json.dumps(json_data, indent=4, separators=(',', ': '))

    def get_profile_info(self, profile):
        ''' Looks for host and port based on the profile provided '''

        config = ConfigParser.RawConfigParser()
        config.read(self.config_file)
        try:
            port = config.get(profile, 'port')
            host = config.get(profile, 'host')
            cert = None if not config.has_option(profile, 'cert') else \
                config.get(profile, 'cert')
            number = 2 if not config.has_option(profile, 'threads') else \
                config.get(profile, 'threads')
        except ConfigParser.NoSectionError:
            raise ImageScannerClientError("The profile {0} cannot be found "
                                          "in {1}".format(profile,
                                                          self.config_file))
        except ConfigParser.NoOptionError as no_option:
            print "No option {0} found in profile "\
                  "{1} in {2}".format(no_option.option,
                                      profile,
                                      self.config_file)
        return host, port, number, cert

    def _make_profile_tuple(self, host, port, number, cert, section):
        ''' Creates the profile_tuple and returns it '''
        return self.profile_tuple(profile=section, host=host, port=port,
                                  cert=None, number=number)

    def return_profiles(self, input_profile_list):
        '''
        Returns a list of tuples with information about the
        input profiles
        '''
        profile_list = []
        config = ConfigParser.ConfigParser()
        config.read(self.config_file)
        for profile in input_profile_list:
            host, port, number, cert = self.get_profile_info(profile)
            if self.threads > 0:
                number = self.threads
            profile_list.append(self._make_profile_tuple(host, port,
                                number, cert, profile))
        return profile_list

    def return_all_profiles(self):
        ''' Returns a list of tuples with host and port information '''

        profile_list = []
        config = ConfigParser.ConfigParser()
        config.read(self.config_file)
        for section in config.sections():
            host, port, number, cert = self.get_profile_info(section)
            profile_list.append(self._make_profile_tuple(host, port, number,
                                cert, section))
        return profile_list

    def get_all_profile_names(self):
        ''' Returns a list of all profile names '''

        profile_names = []
        all_profiles = self.return_all_profiles()
        for profile in all_profiles:
            profile_names.append(profile.profile)
        return profile_names

    def thread_profile_wrapper(self, args):
        ''' Simple wrapper for thread_profiles '''
        return self.thread_profiles(*args)

    def thread_profiles(self, profile, onlyactive, allcontainers,
                        allimages, images):
        ''' Kicks off a scan of for a remote host'''
        scanner = Client(profile.host, profile.port, number=profile.number)
        try:
            if onlyactive:
                results = scanner.scan_all_containers(onlyactive=True)
            elif allcontainers:
                results = scanner.scan_all_containers()
            elif allimages:
                results = scanner.scan_images(all=True)
            else:
                results = scanner.scan_images()
        except ImageScannerClientError as scan_error:
            results = json.dumps({'error': str(scan_error)})

        host_state = results if 'error' in results else \
            scanner.get_docker_json(results['json_url'])
        self.uber_docker[profile.profile] = host_state
        self.num_complete += 1
        self.last_completed = " Completed {0}".format(profile.profile)

    def scan_multiple_hosts(self, profile_list, allimages=False, images=False,
                            allcontainers=False, onlyactive=False,
                            remote_threads=4, threads=0):
        '''
        Scan multiple hosts and returns an uber-docker object
        which is basically an object with one or more docker
        state objects in it.
        '''

        if (threads > 0):
            self.threads = threads

        if (threads < 2 or threads > 4):
            raise ImageScannerClientError("Thread count must be between 2 "
                                          "and 4")

        scan_args = self.args_tuple(allimages=allimages, images=images,
                                    allcontainers=allcontainers,
                                    onlyactive=onlyactive)

        # Check to make sure a scan type was selected
        if not scan_args.allimages and not scan_args.images and not \
                scan_args.allcontainers and not scan_args.onlyactive:
            raise ImageScannerClientError("You must select \
                                          a scan type")

        # Check to make sure only one scan type was selected
        if len([x for x in [scan_args.allimages, scan_args.images,
                            scan_args.allcontainers, scan_args.onlyactive]
                if x is True]) > 1:
            raise ImageScannerClientError("You may only select one \
                                           type of scan")
        # Check profile names are valid
        all_profile_names = self.get_all_profile_names()
        self._check_profile_is_valid(all_profile_names, profile_list)

        # Obtain list of profiles
        profiles = self.return_profiles(profile_list)

        self.num_total = len(profiles)

        # FIXME
        # Make this a variable based on desired number
        pool = ThreadPool(remote_threads)
        pool.map(self.thread_profile_wrapper,
                 [(x, scan_args.onlyactive, scan_args.allcontainers,
                   scan_args.allimages, scan_args.images) for x in profiles])

        with open(self.uber_file_path, 'w') as state_file:
            json.dump(self.uber_docker, state_file)

        return self.uber_docker

    @staticmethod
    def _check_profile_is_valid(all_profile_names, profile_list):
        ''' Checks a list of profiles to make sure they are valid '''
        for profile in profile_list:
            if profile not in all_profile_names:
                raise ImageScannerClientError("Profile {0} is invalid"
                                              .format(profile))

    def load_uber(self):
        ''' Loads the uber json file'''
        uber_obj = json.loads(open(self.uber_file_path).read())
        return uber_obj

    @staticmethod
    def _sum_cves(scan_results_obj):
        ''' Returns the total number of CVEs found'''
        num_cves = 0
        sev_list = ['Critical', 'Important', 'Moderate', 'Low']
        for sev in sev_list:
            if sev in scan_results_obj.keys():
                num_cves += scan_results_obj[sev]['num']
        return num_cves

    def mult_host_mini_pprint(self, uber_obj):
        ''' Pretty print the results of a multi host scan'''
        print "\n"
        print "{0:16} {1:15} {2:12}".format("Host", "Docker ID", "Results")
        print "-" * 50
        prev_host = None
        for host in uber_obj.keys():
            if 'error' in uber_obj[host]:
                print "{0:16} {1:15} {2:12}"\
                    .format(host, "", json.loads(uber_obj[host])['error'])
                print ""
                continue
            for scan_obj in uber_obj[host]['scanned_content']:
                tmp_obj = uber_obj[host]['host_results'][scan_obj]
                is_rhel = tmp_obj['isRHEL']
                if is_rhel:
                    if len(tmp_obj['cve_summary']['scan_results'].keys()) < 1:
                        result = "Clean"
                    else:
                        num_cves = self._sum_cves(tmp_obj['cve_summary']
                                                  ['scan_results'])
                        result = "Has {0} CVEs".format(num_cves)
                else:
                    result = "Not based on RHEL"
                if host is not prev_host:
                    out_host = host
                    prev_host = host
                else:
                    out_host = ""
                print "{0:16} {1:15} {2:12}".format(out_host, scan_obj[:12],
                                                    result)
            print ""
