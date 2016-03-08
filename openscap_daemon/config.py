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
import logging
import shutil
import inspect


class Configuration(object):
    def __init__(self):
        self.config_file = None

        # General section
        self.tasks_dir = os.path.join("/", "var", "lib", "oscapd", "tasks")
        self.results_dir = os.path.join("/", "var", "lib", "oscapd", "results")
        self.work_in_progress_dir = \
            os.path.join("/", "var", "lib", "oscapd", "work_in_progress")
        self.jobs = 4

        # Tools section
        self.oscap_path = ""
        self.oscap_ssh_path = ""
        self.oscap_vm_path = ""
        self.oscap_docker_path = ""
        self.oscap_chroot_path = ""
        self.container_support = True

        # Content section
        self.ssg_path = ""

        # CVEScanner section
        self.fetch_cve = True
        self.fetch_cve_url = ""

    def autodetect_tool_paths(self):
        """This will try a few well-known public paths and change the paths
        accordingly. This method will only try to autodetect paths that are
        empty!

        Auto-detection is implemented for oscap and various related tools and
        SCAP Security Guide content.
        """

        def autodetect_tool_path(possible_names, possible_prefixes=None):
            if possible_prefixes is None:
                possible_prefixes = (
                    os.path.join("/", "usr", "bin"),
                    os.path.join("/", "usr", "local", "bin"),
                    os.path.join("/", "opt", "openscap", "bin")
                )

            for prefix in possible_prefixes:
                for name in possible_names:
                    full_path = os.path.join(prefix, name)
                    if os.path.isfile(full_path) and \
                       os.access(full_path, os.X_OK):
                        logging.info("Autodetected \"%s\" in path \"%s\".",
                                     name, full_path)
                        return full_path

            logging.info(
                "Failed to autodetect tool with name %s in prefixes %s.",
                " or ".join(possible_names), ", ".join(possible_prefixes)
            )
            return ""

        if self.oscap_path == "":
            self.oscap_path = autodetect_tool_path(["oscap", "oscap.exe"])
        if self.oscap_ssh_path == "":
            self.oscap_ssh_path = autodetect_tool_path(["oscap-ssh"])
        if self.oscap_vm_path == "":
            self.oscap_vm_path = autodetect_tool_path(["oscap-vm"])
        if self.oscap_docker_path == "":
            self.oscap_docker_path = autodetect_tool_path(["oscap-docker"])
        if self.oscap_chroot_path == "":
            self.oscap_chroot_path = autodetect_tool_path(["oscap-chroot"])

        if self.container_support:
            # let's verify that we really can enable container support
            self.container_support = False

            try:
                __import__("docker")

                try:
                    from Atomic.mount import DockerMount
                    if "mnt_mkdir" not in \
                            inspect.getargspec(DockerMount.__init__).args:
                        logging.error(
                            "\"Atomic.mount.DockerMount\" has been successfully"
                            " imported but it doesn't support the mnt_mkdir "
                            "argument. Please upgrade your Atomic installation "
                            "to 1.4 or higher. Container scanning functionality"
                            " will be disabled."
                        )

                    logging.info("Successfully imported 'docker' and "
                                 "'Atomic.mount', container scanning enabled.")
                    self.container_support = True

                except ImportError:
                    logging.warning("Can't import the 'Atomic.mount' package. "
                                    "Container scanning functionality will be "
                                    "disabled.")
            except ImportError:
                logging.warning("Can't import the 'docker' package. Container "
                                "scanning functionality will be disabled.")

    def autodetect_content_paths(self):
        def autodetect_content_path(possible_paths):
            for path in possible_paths:
                if os.path.isdir(path):
                    logging.info("Autodetected SCAP content in path \"%s\".",
                                 path)
                    return path

            logging.error(
                "Failed to autodetect SCAP content in paths %s.",
                ", ".join(possible_paths)
            )
            return ""

        if self.ssg_path == "":
            self.ssg_path = autodetect_content_path([
                os.path.join("/", "usr", "share", "xml", "scap", "ssg", "content"),
                os.path.join("/", "usr", "local", "share", "xml", "scap", "ssg", "content"),
                os.path.join("/", "opt", "ssg", "content")
            ])

    def load(self, config_file):
        config = configparser.SafeConfigParser()
        try:
            config.read(config_file)
        except configparser.Error as e:
            logging.error("Configuration file cannot be parsed. %s" % e)
            return

        base_dir = os.path.dirname(config_file)

        def absolutize(path):
            path = str(path)
            if path == "" or os.path.isabs(path):
                return path

            return os.path.normpath(os.path.join(base_dir, path))

        # General section
        try:
            self.tasks_dir = absolutize(config.get("General", "tasks-dir"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.results_dir = absolutize(config.get("General", "results-dir"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.work_in_progress_dir = absolutize(config.get("General", "work-in-progress-dir"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.jobs = config.getint("General", "jobs")
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        # Tools section
        try:
            self.oscap_path = absolutize(config.get("Tools", "oscap"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_ssh_path = absolutize(config.get("Tools", "oscap-ssh"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_vm_path = absolutize(config.get("Tools", "oscap-vm"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_docker_path = absolutize(config.get("Tools", "oscap-docker"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.oscap_chroot_path = absolutize(config.get("Tools", "oscap-chroot"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.container_support = config.get("Tools", "container-support") \
                not in ["no", "0", "false", "False"]
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        # Content section
        try:
            self.ssg_path = absolutize(config.get("Content", "ssg"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        # CVEScanner section
        try:
            self.fetch_cve = config.get("CVEScanner", "fetch-cve") not in \
                ["no", "0", "false", "False"]
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        try:
            self.fetch_cve_url = config.get("CVEScanner", "fetch-cve-url")
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        self.config_file = config_file

    def save_as(self, config_file):
        config = configparser.SafeConfigParser()

        config.add_section("General")
        config.set("General", "tasks-dir", str(self.tasks_dir))
        config.set("General", "results-dir", str(self.results_dir))
        config.set("General", "work-in-progress-dir", str(self.work_in_progress_dir))
        config.set("General", "jobs", str(self.jobs))

        config.add_section("Tools")
        config.set("Tools", "oscap", str(self.oscap_path))
        config.set("Tools", "oscap-ssh", str(self.oscap_ssh_path))
        config.set("Tools", "oscap-vm", str(self.oscap_vm_path))
        config.set("Tools", "oscap-docker", str(self.oscap_docker_path))
        config.set("Tools", "oscap-chroot", str(self.oscap_chroot_path))
        config.set("Tools", "container-support",
                   "yes" if self.container_support else "no")

        config.add_section("Content")
        config.set("Content", "ssg", str(self.ssg_path))

        config.add_section("CVEScanner")
        config.set("CVEScanner", "fetch-cve", "yes" if self.fetch_cve else "no")
        config.set("CVEScanner", "fetch-cve-url", str(self.fetch_cve_url))

        with open(config_file, "w") as f:
            config.write(f)

        self.config_file = config_file

    def save(self):
        self.save_as(self.config_file)

    def prepare_dirs(self):
        if not os.path.exists(self.tasks_dir):
            logging.info(
                "Creating tasks directory at '%s' because it didn't exist.",
                self.tasks_dir
            )
            os.makedirs(self.tasks_dir, 0o750)

        if not os.path.exists(self.results_dir):
            logging.info(
                "Creating results directory at '%s' because it didn't exist.",
                self.results_dir
            )
            os.makedirs(self.results_dir)

        if not os.path.exists(self.work_in_progress_dir):
            logging.info(
                "Creating results work in progress directory at '%s' because "
                "it didn't exist.", self.work_in_progress_dir
            )
            os.makedirs(self.work_in_progress_dir)

        for dir_ in os.listdir(self.work_in_progress_dir):
            full_path = os.path.join(self.work_in_progress_dir, dir_)

            logging.info(
                "Found '%s' in work_in_progress results directory, full path "
                "is '%s'. This is most likely a left-over from an earlier "
                "crash. Deleting...", dir_, full_path
            )

            shutil.rmtree(full_path)
