#!/usr/bin/python2

# Copyright 2015 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# openscap-daemon is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 2.1 of the License, or
# (at your option) any later version.
#
# openscap-daemon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with openscap-daemon.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Martin Preisler <mpreisle@redhat.com>

import os
import os.path

from openscap_daemon import version

from distutils.core import setup


def get_packages():
    # Distutils requires us to list all packages, this is very tedious and prone
    # to errors. This method crawls the hierarchy and gathers all packages.

    ret = ["openscap_daemon"]

    for dirpath, _, files in os.walk("openscap_daemon"):
        if "__init__.py" in files:
            ret.append(dirpath.replace(os.path.sep, "."))

    return ret


setup(
    name="openscap_daemon",
    version=version.VERSION_STRING,
    description="...",
    author="Martin Preisler, Brent Baude and others",
    author_email="mpreisle@redhat.com",
    url="http://www.open-scap.org/",
    packages=get_packages(),
    scripts=[
        os.path.join("bin", "oscapd"),
        os.path.join("bin", "oscapd-cli")
    ],
    data_files=[
        (os.path.join("/", "etc", "dbus-1", "system.d"),
         ["org.oscapd.conf"]),
        (os.path.join("/", "usr", "lib", "systemd", "system"),
         ["oscapd.service"]),
    ]
)
