# Copyright 2017 Red Hat Inc., Durham, North Carolina.
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

VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_PATCH = 10

VERSION_STRING = "%i.%i.%i" % (VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)

__all__ = ["VERSION_MAJOR", "VERSION_MINOR", "VERSION_PATCH", "VERSION_STRING"]
