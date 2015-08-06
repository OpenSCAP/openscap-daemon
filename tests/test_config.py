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

import tests.harness
import os.path
import openscap_daemon.config


# TODO: The harness initializes System and we don't need that here
class ConfigTest(tests.harness.APITest):
    def setup_data(self):
        super(ConfigTest, self).setup_data()

        self.copy_to_data("config_test.ini")

    def test(self):
        super(ConfigTest, self).test()

        config = openscap_daemon.config.Configuration()
        full_path = os.path.abspath(
            os.path.join(self.data_dir_path, "config_test.ini")
        )
        config.load(full_path)
        assert(config.config_file == full_path)

        assert(config.jobs == 8)

        assert(config.oscap_path == "/a/b/c/oscap")
        assert(config.oscap_ssh_path == "/d/e/f/oscap-ssh")
        assert(config.oscap_vm_path == "C:\\openscap\\bin\\oscap-vm")
        assert(config.oscap_docker_path == "/g/h/i/j/oscap-docker")

        assert(config.ssg_path == "/g/h/i/ssg/content")

        saved_full_path = os.path.join(self.data_dir_path, "config_test_s.ini")
        config.save_as(saved_full_path)
        assert(config.config_file == saved_full_path)

        config2 = openscap_daemon.config.Configuration()
        config2.load(saved_full_path)
        assert(config2.config_file == saved_full_path)

        assert(config2.jobs == 8)

        assert(config2.oscap_path == "/a/b/c/oscap")
        assert(config2.oscap_ssh_path == "/d/e/f/oscap-ssh")
        assert(config2.oscap_vm_path == "C:\\openscap\\bin\\oscap-vm")
        assert(config2.oscap_docker_path == "/g/h/i/j/oscap-docker")

        assert(config2.ssg_path == "/g/h/i/ssg/content")


if __name__ == "__main__":
    ConfigTest.run()
