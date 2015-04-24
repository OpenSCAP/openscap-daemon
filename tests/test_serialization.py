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

import tests.harness
import os.path


class SerializationTest(tests.harness.APITest):
    def setup_data(self):
        super(SerializationTest, self).setup_data()
        self.copy_to_data("tasks/1.xml")

    def test(self):
        super(SerializationTest, self).test()

        self.system.load_tasks()
        assert(len(self.system.tasks) == 1)
        self.system.tasks[1].save_as(
            os.path.join(self.data_dir_path, "tasks", "2.xml")
        )
        self.system.load_tasks()
        assert(len(self.system.tasks) == 2)

        assert(
            self.system.tasks[1].is_equivalent_to(self.system.tasks[2])
        )
        self.system.tasks[2].title = "Broken!"
        assert(
            not self.system.tasks[1].is_equivalent_to(self.system.tasks[2])
        )


if __name__ == "__main__":
    SerializationTest.run()
