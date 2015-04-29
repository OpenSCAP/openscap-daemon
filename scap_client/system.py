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
import time
import threading

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
        self.tasks_lock = threading.Lock()

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

            id_ = Task.get_task_id_from_filepath(full_path)

            with self.tasks_lock:
                if id_ not in self.tasks:
                    self.tasks[id_] = Task()

                self.tasks[id_].load(full_path)

    def save_tasks(self):
        with self.tasks_lock:
            for _, task in self.tasks.iteritems():
                task.save()

    def list_task_ids(self):
        ret = []
        with self.tasks_lock:
            ret = self.tasks.keys()

        return ret

    def get_task_title(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.title

    def update(self, reference_datetime=datetime.utcnow()):
        # TODO: This can be changed to support multiple workers in the future
        #       if need arises. Right now it's fully serial but since Tasks are
        #       independent we can do them in parallel, we can never update the
        #       same Task two times in parallel though.

        # Locking because self.tasks list cannot change while we are iterating,
        # changing it would cause undefined behavior.
        # The tasks themselves *can* change but they cannot be added or removed
        # from the self.tasks list.
        with self.tasks_lock:
            for _, task in self.tasks.iteritems():
                task.update(
                    reference_datetime,
                    self.results_dir,
                    self.work_in_progress_results_dir
                )

    def update_worker(self):
        # TODO: Sleep until necessary to save CPU cycles

        while True:
            print("Worker active")
            self.update()
            time.sleep(1)

    def generate_guide_for_task(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.generate_guide()

    def generate_report_for_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.generate_report_for_result(
            self.results_dir,
            result_id
        )
