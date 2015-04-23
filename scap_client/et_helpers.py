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


def get_element_text(parent, element_name, default=None):
    ret = None
    for element in parent.findall(element_name):
        if ret is not None:
            raise RuntimeError(
                "Found multiple '%s' elements." % (element_name)
            )

        ret = element.text

    if ret is None:
        return default

    return ret


def get_element_attr(parent, element_name, attr_name, default=None):
    ret = None
    for element in parent.findall(element_name):
        if ret is not None:
            raise RuntimeError(
                "Found multiple '%s' elements with '%s' attributes." %
                (element_name, attr_name)
            )

        ret = element.get(attr_name)

    if ret is None:
        return default

    return ret
