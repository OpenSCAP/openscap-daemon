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


def get_element(parent, element_name):
    ret = None
    for element in parent.findall(element_name):
        if ret is not None:
            raise RuntimeError(
                "Found multiple '%s' elements." %
                (element_name)
            )

        ret = element

    if ret is None:
        raise RuntimeError(
            "Found no element of tag '%s'!" %
            (element_name)
        )

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


# taken from ElementLib and slightly tweaked for readability
def indent(elem, level=0, indent_char="    "):
    i = "\n" + level * indent_char
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + indent_char

        last = None
        for e in elem:
            indent(e, level + 1)
            if not e.tail or not e.tail.strip():
                e.tail = i + indent_char

            last = e

        if not last.tail or not last.tail.strip():
            last.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i
