# Copyright (C) 2016 Red Hat Inc., Durham, North Carolina.
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

try:
    # Python2 imports
    import urlparse
    import urllib2 as urllib

except ImportError:
    # Python3 imports
    import urllib.parse as urlparse
    import urllib.request as urllib

import os
import os.path
import time
import datetime
import logging
import bz2
import threading


class CVEFeedManager(object):
    """Class to obtain the CVE data provided by RH and possibly other vendors.
    The CVE data is used to scan for CVEs using OpenSCAP
    """

    default_url = "https://www.redhat.com/security/data/oval/"

    class HeadRequest(urllib.Request):
        def get_method(self):
            return "HEAD"

    def __init__(self, dest="/tmp"):
        self.dest = dest
        self.hdr = {"User-agent": "Mozilla/5.0"}
        self.hdr2 = [("User-agent", "Mozilla/5.0")]
        self.url = CVEFeedManager.default_url
        self.remote_dist_cve_name = "com.redhat.rhsa-RHEL{0}.xml.bz2"
        self.local_dist_cve_name = "com.redhat.rhsa-RHEL{0}.xml"
        self.dists = [5, 6, 7]
        self.remote_pattern = '%a, %d %b %Y %H:%M:%S %Z'

        self.fetch_enabled = True
        # check for fresh CVE feeds at most every 10 minutes
        self.fetch_timeout = 10 * 60
        # A map of remote URIs to the time we last checked them for fresh
        # content.
        self.fetch_last_checked = {}
        # Let us only check for fresh CVEs once at a time
        self.fetch_lock = threading.Lock()

    def _parse_http_headers(self, http_headers):
        """Returns dictionary containing HTTP headers with lowercase keys
        """

        headers_dict = dict(http_headers)
        return dict((key.lower(), value) for key, value in headers_dict.items())

    def _print_no_last_modified_warning(self, url):
        logging.warning(
            "Warning: Response header of HTTP doesn't contain "
            "\"last-modified\" field. Cannot determine version"
            " of remote file \"{0}\"".format(url)
        )

    def _is_cache_same(self, local_file, remote_url):
        """Checks if the local cache version and the upstream
        version is the same or not. If they are the same,
        returns True; else False.
        """

        with self.fetch_lock:
            if not os.path.exists(local_file):
                logging.debug(
                    "No local file cached, will fetch {0}".format(remote_url)
                )
                return False

            last_checked = self.fetch_last_checked.get(remote_url, 0)
            now = time.time()

            if now - last_checked <= self.fetch_timeout:
                logging.debug(
                    "Checked for fresh version of '%s' just %f seconds ago. "
                    "Will wait %f seconds before checking again.",
                    remote_url, now - last_checked,
                    self.fetch_timeout - now + last_checked
                )
                return True

            opener = urllib.OpenerDirector()
            opener.add_handler(urllib.HTTPHandler())
            opener.add_handler(urllib.HTTPSHandler())
            opener.add_handler(urllib.HTTPDefaultErrorHandler())
            # Extra for handling redirects
            opener.add_handler(urllib.HTTPErrorProcessor())
            opener.add_handler(urllib.HTTPRedirectHandler())
            # Add the header
            opener.addheaders = self.hdr2
            # Grab the header
            try:
                res = opener.open(CVEFeedManager.HeadRequest(remote_url))
                headers = self._parse_http_headers(res.info())
                res.close()
                remote_ts = headers['last-modified']

            except urllib.HTTPError as http_error:
                logging.debug(
                    "Cannot send HTTP HEAD request to get \"last-modified\" "
                    "attribute of remote content file.\n{0} - {1}"
                    .format(http_error.code, http_error.reason)
                )
                return False

            except KeyError:
                self._print_no_last_modified_warning(remote_url)
                return False

            self.fetch_last_checked[remote_url] = time.time()

            # The remote's datetime
            remote_dt = datetime.datetime.strptime(
                remote_ts, self.remote_pattern
            )
            # Get the locals datetime from the file's mtime, converted to UTC
            local_dt = datetime.datetime.utcfromtimestamp(
                os.stat(local_file).st_mtime
            )

            # Giving a two second comfort zone
            # Else we declare they are different
            if (remote_dt - local_dt).seconds > 2:
                logging.info("Had a local version of {0} "
                             "but it wasn't new enough".format(local_file))
                return False

            logging.debug("File {0} is same as upstream".format(local_file))
            return True

    def get_rhel_cve_feed(self, dist):
        """Given a distribution number (i.e. 7), it will fetch the
        distribution specific data file if upstream has a newer
        input file. Returns the path of file.

        If we already have a cached version that is fresh it will just
        return the path.
        """

        local_file = os.path.join(
            self.dest, self.local_dist_cve_name.format(dist)
        )
        if not self.fetch_enabled:
            return local_file

        remote_url = urlparse.urljoin(
            self.url, self.remote_dist_cve_name.format(dist)
        )
        if self._is_cache_same(local_file, remote_url):
            return local_file

        _url = urllib.Request(remote_url, headers=self.hdr)

        try:
            resp = urllib.urlopen(_url)

        except Exception as url_error:
            raise Exception("Unable to fetch CVE inputs due to {0}"
                            .format(url_error))

        fh = open(local_file, "wb")
        fh.write(bz2.decompress(resp.read()))
        fh.close()

        # Correct Last-Modified timestamp
        headers = self._parse_http_headers(resp.info())
        resp.close()
        try:
            remote_ts = headers['last-modified']
            epoch = datetime.datetime.utcfromtimestamp(0)
            remote_dt = datetime.datetime.strptime(remote_ts, self.remote_pattern)
            seconds_epoch = (remote_dt - epoch).total_seconds()
            os.utime(local_file, (seconds_epoch, seconds_epoch))

        except KeyError:
            self._print_no_last_modified_warning(remote_url)

        return local_file

    def fetch_all_rhel_cve_feeds(self):
        """Fetches all the the distribution specific data used for
        input with openscap cve scanning and returns a list
        of those files.
        """

        cve_files = []
        for dist in self.dists:
            cve_files.append(self.get_cve_feed(dist))
        return cve_files

    def get_cve_feed(self, cpe_ids):
        if "cpe:/o:redhat:enterprise_linux:7" in cpe_ids:
            return self.get_rhel_cve_feed(7)
        elif "cpe:/o:redhat:enterprise_linux:6" in cpe_ids:
            return self.get_rhel_cve_feed(6)
        elif "cpe:/o:redhat:enterprise_linux:5" in cpe_ids:
            return self.get_rhel_cve_feed(5)

        raise RuntimeError(
            "Can't find a supported CPE ID in %s" % (", ".join(cpe_ids))
        )

    def get_cve_feed_last_updated(self, cpe_ids):
        local_file = self.get_cve_feed(cpe_ids)
        assert(os.path.exists(local_file))
        # local timestamp, local timezone datetime
        return datetime.datetime.fromtimestamp(os.path.getmtime(local_file))
