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
import logging
import Queue

from scap_client.task import Task


class System(object):
    @staticmethod
    def prepare_data_dir(data_dir):
        tasks_dir = os.path.join(data_dir, "tasks")
        results_dir = os.path.join(data_dir, "results")
        work_in_progress_results_dir = \
            os.path.join(results_dir, "work_in_progress")

        if not os.path.exists(data_dir):
            logging.info(
                "Creating data directory at '%s' because it doesn't exist." %
                (data_dir)
            )
            os.mkdir(data_dir)

        if not os.path.exists(tasks_dir):
            logging.info(
                "Creating tasks directory at '%s' because it doesn't exist." %
                (tasks_dir)
            )
            os.mkdir(tasks_dir)

        if not os.path.exists(results_dir):
            logging.info(
                "Creating results directory at '%s' because it doesn't exist." %
                (results_dir)
            )
            os.mkdir(results_dir)

        if not os.path.exists(work_in_progress_results_dir):
            logging.info(
                "Creating results work in progresss directory at '%s' because "
                "it doesn't exist." %
                (work_in_progress_results_dir)
            )
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
        logging.info("Loading task definitions from '%s'..." % (self.tasks_dir))
        task_files = os.listdir(self.tasks_dir)

        task_count = 0
        for task_file in task_files:
            if not task_file.endswith(".xml"):
                logging.warning(
                    "Found '%s' in task definitions directory '%s'. Paths "
                    "not ending with '.xml' are unexpected in the task "
                    "definitions directory " % (task_file, self.tasks_dir)
                )
                continue

            full_path = os.path.join(self.tasks_dir, task_file)

            if not os.path.isfile(full_path):
                logging.warning(
                    "Found '%s' in task definitions directory '%s'. This path "
                    "is not a file. Only files are expected in the task "
                    "definitions directory " % (full_path, self.tasks_dir)
                )
                continue

            id_ = Task.get_task_id_from_filepath(full_path)

            with self.tasks_lock:
                if id_ not in self.tasks:
                    self.tasks[id_] = Task()

                self.tasks[id_].load(full_path)
                task_count += 1

        logging.info(
            "Successfully loaded %i task definitions." % (task_count)
        )

    def save_tasks(self):
        logging.info("Saving task definitions to '%s'..." % (self.tasks_dir))
        task_count = 0
        with self.tasks_lock:
            for _, task in self.tasks.iteritems():
                task.save()
                task_count += 1

        logging.info(
            "Successfully saved %i task definitions." % (task_count)
        )

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

    def update(self, reference_datetime=None, max_jobs=4):
        """Evaluates all currently outstanding tasks and returns.
        Outstanding task means it's not_before is lower than reference_datetime,
        and it is not disabled. Tasks can be processed in parallel if their
        targets differ. No two tasks with the same target will be run in
        parallel regardless of max_jobs setting.

        reference_datetime - Which date/time should be used to plan tasks.
        max_jobs - Use at most this amount of threads to evaluate.
        """

        if reference_datetime is None:
            reference_datetime = datetime.utcnow()

        logging.debug(
            "Updating system, reference_datetime='%s'." %
            (str(reference_datetime))
        )

        # We need to organize tasks by targets to avoid running 2 tasks on the
        # same target at the same time.
        # self.tasks needs to be locked, so that the list doesn't change while
        # we construct the buckets. The tasks themselves can be changed while we
        # are organizing them but if their targets change we may end up with a
        # schedule that is not perfect. That is the trade-off we are making.
        tasks_by_target = dict()
        with self.tasks_lock:
            for task in self.tasks.itervalues():
                if task.target not in tasks_by_target:
                    tasks_by_target[task.target] = []

                tasks_by_target[task.target].append(task)

            logging.debug(
                "Organized %i task definitions into %i buckets by target." %
                (len(self.tasks), len(tasks_by_target.keys()))
            )

        # Each different target will be a queue item
        queue = Queue.Queue()
        for target, target_tasks in tasks_by_target.iteritems():
            queue.put_nowait((target, target_tasks))

        # If any error occurs we want to cancel all jobs
        error_encountered = threading.Event()

        def update_tasks_of_target():
            while True:
                try:
                    (target, target_tasks) = queue.get(False)

                    logging.debug(
                        "Started updating %i tasks of target '%s'." %
                        (len(target_tasks), target)
                    )

                    # In case an error occurs in any of the jobs, we short
                    # circuit everything.
                    if not error_encountered.is_set():
                        try:
                            for task in target_tasks:
                                logging.debug(
                                    "Updating task '%s' of target of target "
                                    "'%s'." % (task.id_, target)
                                )

                                task.update(
                                    reference_datetime,
                                    self.results_dir,
                                    self.work_in_progress_results_dir
                                )

                        except:
                            logging.exception(
                                "Error while processing tasks of target '%s':\n"
                                "%s" % (target)
                            )
                            error_encountered.set()

                    # If an exception was caught above, fake the task as done
                    # to allow the jobs to end
                    queue.task_done()
                    logging.debug(
                        "Finished updating %i tasks of target '%s'." %
                        (len(target_tasks), target)
                    )

                except Queue.Empty:
                    break

        jobs = []
        assert(max_jobs > 0)
        # It makes no sense to spawn more jobs than we have targets
        number_of_jobs = min(max_jobs, queue.qsize)
        for job_id in xrange(number_of_jobs):
            job = threading.Thread(
                name="Task update job %i" % (job_id),
                target=update_tasks_of_target
            )
            jobs.append(job)
            job.start()
            logging.debug(
                "Started task update job %i." % (job_id)
            )

        queue.join()

        if error_encountered.is_set():
            # TODO: Do we need to report this again?
            pass

    def update_worker(self):
        # TODO: Sleep until necessary to save CPU cycles

        while True:
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
