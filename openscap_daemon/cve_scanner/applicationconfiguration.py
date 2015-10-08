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

''' Class to handle references '''

# TODO: Integrate this to openscap_daemon.config package

from openscap_daemon.cve_scanner.scanner_error import ImageScannerClientError
import docker


class Singleton(object):
    ''' Singleton class to pass references'''
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            instance = super(Singleton, cls).__new__(cls)
            instance._singleton_init(*args, **kwargs)
            cls._instance = instance
        return cls._instance

    def __init__(self, *args, **kwargs):
        pass

    def _singleton_init(self, *args, **kwargs):
        """Initialize a singleton instance before it is registered."""
        pass


class ApplicationConfiguration(Singleton):
    '''Application Configuration'''
    def _singleton_init(self, parserargs=None):
        ''' Init for Application Configuration '''
        super(ApplicationConfiguration, self)._singleton_init()
        self.workdir = parserargs.workdir
        self.logfile = parserargs.logfile
        self.number = parserargs.number
        self.reportdir = parserargs.reportdir
        self.onlycache = parserargs.onlycache
        self.fcons = None
        self.cons = None
        self.images = None
        self.allimages = None
        self.return_json = None
        self.conn = self.ValidateHost(parserargs.host)
        self.parserargs = parserargs
        self.json_url = None
        self.os_release = None
        # "" means we will use oscap-docker defaults, else a string with URL
        # is expected. example: "https://www.redhat.com/security/data/oval/"
        self.fetch_cve_url = parserargs.fetch_cve_url

    def ValidateHost(self, host):
        ''' Validates if the defined docker host is running'''
        try:
            client = docker.Client(base_url=host, timeout=11)
            if not client.ping():
                raise(Exception)
        except Exception:
            error = "Cannot connect to the Docker daemon. Is it running on " \
                    "this host"
            client = None
            raise ImageScannerClientError(error)
        return client

    def __init__(self, parserargs=None):
        ''' init '''
        pass
