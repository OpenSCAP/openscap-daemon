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

try:
    import ConfigParser as configparser
except ImportError:
    # ConfigParser has been renamed to configparser in python3
    import configparser

import os
import os.path

class Configuration(object):
    def __init__(self):
        self.config_file = None

        self.jobs = 4

        self.oscap_path = ""
        self.oscap_ssh_path = ""
        # TODO: oscap-vm doesn't even exist yet
        self.oscap_vm_path = ""
        self.oscap_docker_path = ""

        self.ssg_path = ""

    def autodetect_paths(self):
        """This will try a few well-known public paths and change the paths
        accordingly. This method will only try to autodetect paths that are
        empty!

        Auto-detection is implemented for oscap and various related tools and
        SCAP Security Guide content.
        """

        def autodetect_tool_path(
            possible_names,
            possible_prefixes=None
        ):
            if possible_prefixes is None:
                possible_prefixes = (
                    os.path.join("/", "usr", "bin"),
                    os.path.join("/", "usr", "local", "bin"),
                    os.path.join("/", "opt", "openscap", "bin")
                )

            ret = ""

            for prefix in possible_prefixes:
                for name in possible_names:
                    full_path = os.path.join(prefix, name)
                    if os.path.isfile(full_path) and \
                       os.access(full_path, os.X_OK):
                        ret = full_path
                        break

            return ret

        def autodetect_content_path(possible_paths):
            for path in possible_paths:
                if os.path.isdir(path):
                    return path

            return ""

        if self.oscap_path == "":
            self.oscap_path = autodetect_tool_path(["oscap", "oscap.exe"])
        if self.oscap_ssh_path == "":
            self.oscap_ssh_path = autodetect_tool_path(["oscap-ssh"])
        if self.oscap_vm_path == "":
            self.oscap_vm_path = autodetect_tool_path(["oscap-vm"])
        if self.oscap_docker_path == "":
            self.oscap_docker_path = autodetect_tool_path(["oscap-docker"])

        if self.ssg_path == "":
            self.ssg_path = autodetect_content_path([
                os.path.join("/", "usr", "share", "xml", "scap", "ssg", "content"),
                os.path.join("/", "usr", "local", "share", "xml", "scap", "ssg", "content"),
                os.path.join("/", "opt", "ssg", "content")
            ])

    def load(self, config_file):
        config = configparser.SafeConfigParser()
        config.read(config_file)

        try:
            self.jobs = config.getint("General", "jobs")
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_path = str(config.get("Tools", "oscap"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_ssh_path = str(config.get("Tools", "oscap-ssh"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_vm_path = str(config.get("Tools", "oscap-vm"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_docker_path = str(config.get("Tools", "oscap-docker"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.ssg_path = str(config.get("Content", "ssg"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        self.config_file = config_file

    def save_as(self, config_file):
        config = configparser.SafeConfigParser()

        config.add_section("General")
        config.set("General", "jobs", str(self.jobs))

        config.add_section("Tools")
        config.set("Tools", "oscap", str(self.oscap_path))
        config.set("Tools", "oscap-ssh", str(self.oscap_ssh_path))
        config.set("Tools", "oscap-vm", str(self.oscap_vm_path))
        config.set("Tools", "oscap-docker", str(self.oscap_docker_path))

        config.add_section("Content")
        config.set("Content", "ssg", str(self.ssg_path))

        with open(config_file, "w") as f:
            config.write(f)

        self.config_file = config_file

    def save(self):
        self.save_as(self.config_file)