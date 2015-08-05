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

    def autodetect_tool_paths(self):
        """This will try a few well-known public paths and change the paths
        accordingly. This method will only try to autodetect paths that are
        empty!
        """

        def autodetect_tool_path(
            possible_names,
            possible_prefixes=None
        ):
            if possible_prefixes is None:
                possible_prefixes = (
                    os.path.join("usr", "bin"),
                    os.path.join("usr", "local", "bin"),
                    os.path.join("opt", "openscap", "bin")
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

        if self.oscap_path == "":
            self.oscap_path = autodetect_tool_path(["oscap", "oscap.exe"])

        if self.oscap_ssh_path == "":
            self.oscap_ssh_path = autodetect_tool_path(["oscap-ssh"])

        if self.oscap_vm_path == "":
            self.oscap_vm_path = autodetect_tool_path(["oscap-vm"])

        if self.oscap_docker_path == "":
            self.oscap_docker_path = autodetect_tool_path(["oscap-docker"])

    def load(self, config_file):
        config = configparser.SafeConfigParser()
        config.read(config_file)

        try:
            self.jobs = config.getint("General", "jobs")
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_path = str(config.get("Paths", "oscap"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_ssh_path = str(config.get("Paths", "oscap-ssh"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_vm_path = str(config.get("Paths", "oscap-vm"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_docker_path = str(config.get("Paths", "oscap-docker"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        self.config_file = config_file

    def save_as(self, config_file):
        config = configparser.SafeConfigParser()

        config.add_section("General")
        config.set("General", "jobs", str(self.jobs))

        config.add_section("Paths")
        config.set("Paths", "oscap", str(self.oscap_path))
        config.set("Paths", "oscap-ssh", str(self.oscap_ssh_path))
        config.set("Paths", "oscap-vm", str(self.oscap_vm_path))
        config.set("Paths", "oscap-docker", str(self.oscap_docker_path))

        with open(config_file, "w") as f:
            config.write(f)

        self.config_file = config_file

    def save(self):
        self.save_as(self.config_file)