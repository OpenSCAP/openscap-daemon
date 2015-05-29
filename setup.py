#!/usr/bin/python2

# Copyright 2015 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# scap-client is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 2.1 of the License, or
# (at your option) any later version.
#
# scap-client is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with scap-client.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Martin Preisler <mpreisle@redhat.com>

import os
import os.path

from scap_client import version

from distutils.core import setup


def get_packages():
    # Distutils requires us to list all packages, this is very tedious and prone
    # to errors. This method crawls the hierarchy and gathers all packages.

    ret = ["scap_client"]

    for dirpath, _, files in os.walk("scap_client"):
        if "__init__.py" in files:
            ret.append(dirpath.replace(os.path.sep, "."))

    return ret


setup(
    name = "scap-client",
    version = version.VERSION_STRING,
    description = "...",
    author = "Martin Preisler and others (see AUTHORS)",
    author_email = "mpreisle@redhat.com",
    url = "http://www.open-scap.org/",
    packages = get_packages(),
    scripts = ["bin/scap-client", "bin/scap-client-daemon"]
)
