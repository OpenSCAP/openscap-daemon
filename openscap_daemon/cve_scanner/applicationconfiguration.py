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
# You should have received a copy of the GNU Lesser General Public License
# along with openscap-daemon.  If not, see <http://www.gnu.org/licenses/>.

# TODO: Integrate this to openscap_daemon.config package

from openscap_daemon.cve_scanner.scanner_error import ImageScannerClientError


class ApplicationConfiguration(object):
    '''Application Configuration'''
    def __init__(self, parserargs=None):
        ''' Init for Application Configuration '''
        self.workdir = parserargs.workdir
        self.logfile = parserargs.logfile
        self.number = parserargs.number
        self.reportdir = parserargs.reportdir
        self.fetch_cve = parserargs.fetch_cve
        self.fcons = None
        self.cons = None
        self.images = None
        self.allimages = None
        self.return_json = None
        self.conn = self.ValidateHost(parserargs.host)
        self.parserargs = parserargs
        self.json_url = None
        # "" means we will use oscap-docker defaults, else a string with URL
        # is expected. example: "https://www.redhat.com/security/data/oval/"
        self.fetch_cve_url = parserargs.fetch_cve_url

    def ValidateHost(self, host):
        ''' Validates if the defined docker host is running'''
        try:
            import docker
        except ImportError:
            error = "Can't import 'docker' package. Has docker been installed?"
            raise ImageScannerClientError(error)

        client = docker.Client(base_url=host, timeout=11)
        if not client.ping():
            error = "Cannot connect to the Docker daemon. Is it running " \
                "on this host?"
            raise ImageScannerClientError(error)
        return client
