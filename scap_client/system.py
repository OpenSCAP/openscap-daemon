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
from datetime import datetime

from scap_client.task import Task


class System(object):
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.tasks_dir = os.path.join(self.data_dir, "tasks")
        self.results_dir = os.path.join(self.data_dir, "results")

        self.tasks = dict()

    def load_tasks(self):
        task_files = os.listdir(self.tasks_dir)

        for task_file in task_files:
            if not task_file.endswith(".xml"):
                # TODO
                continue

            full_path = os.path.join(self.tasks_dir, task_file)

            if not os.path.isfile(full_path):
                # TODO
                continue

            task = Task()
            task.load(full_path)
            self.tasks[full_path] = task

    def save_tasks(self):
        for _, task in self.tasks.iteritems():
            task.save()

    def tick(self, reference_datetime=datetime.utcnow()):
        for _, task in self.tasks.iteritems():
            task.tick(reference_datetime, self.results_dir)
