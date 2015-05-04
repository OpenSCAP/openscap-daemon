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
from scap_client import oscap_helpers


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

    def get_ssg_choices(self):
        # TODO: This has to be configurable in the future
        ssg_path = os.path.join(
            "/", "usr", "share", "xml", "scap", "ssg", "content"
        )

        ret = []
        for ssg_file in os.listdir(ssg_path):
            full_path = os.path.join(ssg_path, ssg_file)

            if not os.path.isfile(full_path):
                continue

            if not full_path.endswith("-ds.xml"):
                continue

            ret.append(full_path)

        return sorted(ret)

    def get_profile_choices_for_input(self, input_file, tailoring_file):
        return oscap_helpers.get_profile_choices_for_input(
            input_file, tailoring_file
        )

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
                (len(self.tasks), len(tasks_by_target))
            )

        # Each different target will be a queue item
        queue = Queue.Queue()
        for target, target_tasks in tasks_by_target.iteritems():
            queue.put_nowait((target, target_tasks))

        # If any error occurs we want to cancel all jobs
        error_encountered = threading.Event()

        def update_tasks_of_target(job_id):
            logging.debug("Task update job %i started." % (job_id))

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
                                "Error while processing tasks of target '%s'" %
                                (target)
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

            logging.debug("Task update job %i finished." % (job_id))

        jobs = []
        assert(max_jobs > 0)
        # It makes no sense to spawn more jobs than we have targets
        number_of_jobs = min(max_jobs, len(tasks_by_target))
        for job_id in xrange(number_of_jobs):
            job = threading.Thread(
                name="Task update job %i" % (job_id),
                target=update_tasks_of_target,
                args=(job_id,)
            )
            jobs.append(job)
            job.start()

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

    def get_task_result_ids(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        # TODO: Is this a race condition? look into task.update
        return task.list_result_ids(self.results_dir)

    def get_arf_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_arf_of_result(
            self.results_dir,
            result_id
        )

    def get_stdout_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_stdout_of_result(
            self.results_dir,
            result_id
        )

    def get_stderr_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_stderr_of_result(
            self.results_dir,
            result_id
        )

    def get_exit_code_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_exit_code_of_result(
            self.results_dir,
            result_id
        )

    def generate_report_for_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.generate_report_for_result(
            self.results_dir,
            result_id
        )
