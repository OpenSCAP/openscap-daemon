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
    @staticmethod
    def prepare_data_dir(data_dir):
        tasks_dir = os.path.join(data_dir, "tasks")
        results_dir = os.path.join(data_dir, "results")
        work_in_progress_results_dir = \
            os.path.join(results_dir, "work_in_progress")

        # TODO: Warn about created dirs?
        if not os.path.exists(data_dir):
            os.mkdir(data_dir)

        if not os.path.exists(tasks_dir):
            os.mkdir(tasks_dir)

        if not os.path.exists(results_dir):
            os.mkdir(results_dir)

        if not os.path.exists(work_in_progress_results_dir):
            os.mkdir(work_in_progress_results_dir)

    def __init__(self, data_dir):
        System.prepare_data_dir(data_dir)

        self.data_dir = data_dir
        self.tasks_dir = os.path.join(self.data_dir, "tasks")
        self.results_dir = os.path.join(self.data_dir, "results")
        self.work_in_progress_results_dir = \
            os.path.join(self.results_dir, "work_in_progress")

        self.tasks = dict()

    def load_tasks(self):
        task_files = os.listdir(self.tasks_dir)

        for task_file in task_files:
            if not task_file.endswith(".xml"):
                # TODO: warn
                continue

            full_path = os.path.join(self.tasks_dir, task_file)

            if not os.path.isfile(full_path):
                # TODO: warn
                continue

            task = Task()
            task.load(full_path)
            self.tasks[full_path] = task

    def save_tasks(self):
        for _, task in self.tasks.iteritems():
            task.save()

    def update(self, reference_datetime=datetime.utcnow()):
        # TODO: This can be changed to support multiple workers in the future
        #       if need arises. Right now it's fully serial but since Tasks are
        #       independent we can do them in parallel, we can never update the
        #       same Task two times in parallel though.

        for _, task in self.tasks.iteritems():
            task.update(
                reference_datetime,
                self.results_dir,
                self.work_in_progress_results_dir
            )
