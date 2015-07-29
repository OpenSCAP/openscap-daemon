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

import os
import os.path
from datetime import datetime
import threading
import logging
import Queue
import shutil

from openscap_daemon.task import Task
from openscap_daemon import oscap_helpers


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

        for dir_ in os.listdir(work_in_progress_results_dir):
            full_path = os.path.join(work_in_progress_results_dir, dir_)

            logging.info(
                "Found '%s' in work_in_progress results directory, full path "
                "is '%s'. This is most likely a left-over from an earlier "
                "crash. Deleting..." %
                (dir_, full_path)
            )

            shutil.rmtree(full_path)

    def __init__(self, data_dir):
        System.prepare_data_dir(data_dir)

        self.data_dir = os.path.abspath(data_dir)
        self.tasks_dir = os.path.join(self.data_dir, "tasks")
        self.results_dir = os.path.join(self.data_dir, "results")
        self.work_in_progress_results_dir = \
            os.path.join(self.results_dir, "work_in_progress")

        self.tasks = dict()
        self.tasks_lock = threading.Lock()

        self.update_wait_cond = threading.Condition()

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

        with self.update_wait_cond:
            self.update_wait_cond.notify_all()

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

    def create_task(self):
        task_id = 1

        with self.tasks_lock:
            while task_id in self.tasks:
                task_id += 1

            task = Task()
            task.id_ = task_id
            task.config_file = os.path.join(
                self.tasks_dir, "%i.xml" % (task_id)
            )

            self.tasks[task_id] = task

            # We do not save the task on purpose, empty tasks are worthless.
            # The task will be saved to disk as soon as one of its properties is
            # set.
            # task.save()

            logging.info("Created new empty task with ID '%i'." % (task_id))

            # Do not notify the update_wait_cond, the task is disabled so it
            # doesn't affect the schedule in any way

            # with self.update_wait_cond:
            #    self.update_wait_cond.notify_all()

        return task_id

    def remove_task(self, task_id):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]
            if task.enabled:
                raise RuntimeError(
                    "Can't remove enabled task '%i'. Please disable it first." %
                    (task_id)
                )

            result_ids = task.list_result_ids(self.results_dir)
            if len(result_ids) > 0:
                raise RuntimeError(
                    "Can't remove task '%i', in has %i results stored. "
                    "Please remove all the results first." %
                    (task_id, len(result_ids))
                )

            del self.tasks[task_id]

        os.remove(os.path.join(self.tasks_dir, "%i.xml" % (task_id)))
        logging.info("Removed task '%i'." % (task_id))

    def set_task_enabled(self, task_id, enabled):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.enabled = bool(enabled)
            task.save()

        logging.info(
            "%s task with ID %i." %
            ("Enabled" if enabled else "Disabled", task_id)
        )

        if task.enabled:
            with self.update_wait_cond:
                self.update_wait_cond.notify_all()

    def set_task_title(self, task_id, title):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.title = title
            task.save()

        logging.info(
            "Set title of task with ID %i to '%s'." %
            (task_id, title)
        )

    def get_task_title(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.title

    def set_task_target(self, task_id, target):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.target = target
            task.save()

        logging.info(
            "Set target of task with ID %i to '%s'." %
            (task_id, target)
        )

    def get_task_target(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.target

    def set_task_input(self, task_id, input_):
        """input can be an absolute file path or the XML source itself. This is
        autodetected.
        """

        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            if input_ is None or os.path.isabs(input_):
                task.set_input_file(input_)

                logging.info(
                    "Set input content of task with ID %i to file '%s'." %
                    (task_id, input_)
                )

            else:
                task.set_input_contents(input_)

                logging.info(
                    "Set input content of task with ID %i to custom XML."
                    (task_id)
                )

            task.save()

    def set_task_tailoring(self, task_id, tailoring):
        """tailoring can be an absolute file path or the XML source itself.
        This is autodetected.
        """

        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            if tailoring is None or os.path.isabs(tailoring):
                task.set_tailoring_file(tailoring)

                logging.info(
                    "Set tailoring content of task with ID %i to file '%s'." %
                    (task_id, tailoring)
                )

            else:
                task.set_tailoring_contents(tailoring)

                logging.info(
                    "Set tailoring content of task with ID %i to custom XML."
                    (task_id)
                )

            task.save()

    def set_task_profile_id(self, task_id, profile_id):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.profile_id = profile_id
            task.save()

        logging.info(
            "Set profile ID of task with ID %i to '%s'." %
            (task_id, profile_id)
        )

    def set_task_online_remediation(self, task_id, remediation_enabled):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.online_remediation = bool(remediation_enabled)
            task.save()

        logging.info(
            "%s online remedition of task with ID %i." %
            ("Enabled" if remediation_enabled else "Disabled", task_id)
        )

    def set_task_schedule_not_before(self, task_id, schedule_not_before):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.schedule_not_before = schedule_not_before
            task.save()

        logging.info(
            "Set schedule not before of task with ID %i to %s." %
            (task_id, schedule_not_before)
        )

        # This changes the schedule which potentially obsoletes the precomputed
        # schedule. Make sure we re-schedule everything.
        if task.enabled:
            with self.update_wait_cond:
                self.update_wait_cond.notify_all()

    def set_task_schedule_repeat_after(self, task_id, schedule_repeat_after):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.schedule_repeat_after = schedule_repeat_after
            task.save()

        logging.info(
            "Set schedule repeat after of task with ID %i to %s." %
            (task_id, schedule_repeat_after)
        )

        # This changes the schedule which potentially obsoletes the precomputed
        # schedule. Make sure we re-schedule everything.
        if task.enabled:
            with self.update_wait_cond:
                self.update_wait_cond.notify_all()

    def get_closest_datetime(self, reference_datetime):
        ret = None

        with self.tasks_lock:
            for task in self.tasks.itervalues():
                next_update_time = task.get_next_update_time(reference_datetime)
                if next_update_time is None:
                    continue

                if ret is None or next_update_time < ret:
                    ret = next_update_time

        return ret

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
        # TODO: If there is a task scheduled to run at (t - e) and many tasks
        # scheduled to run at t and e is a very small number, it can happen that
        # the first task is evaluated and blocks evaluation of the other tasks,
        # the other tasks will all be evaluated in parallel later when the first
        # task finishes. This is a nasty problem and an edge-case, so we keep it
        # unsolved for now.

        while True:
            reference_datetime = datetime.now()

            closest_datetime = self.get_closest_datetime(reference_datetime)
            if closest_datetime is None:
                with self.update_wait_cond:
                    logging.debug(
                        "No task is scheduled to run. Sleeping for an hour. "
                        "Interruptible if task specs change."
                    )
                    self.update_wait_cond.wait(60 * 60)

            else:
                time_to_wait = closest_datetime - reference_datetime
                # because of ntp, daylight savings, etc, lets be safe
                # and reschedule every hour at least
                seconds_to_wait = min(60 * 60, time_to_wait.total_seconds())

                if seconds_to_wait > 0:
                    with self.update_wait_cond:
                        logging.debug(
                            "Closest task action in %s. Sleeping until then. "
                            "Interruptible if task specs change." %
                            (time_to_wait)
                        )
                        self.update_wait_cond.wait(seconds_to_wait)

            self.update(reference_datetime)

    def generate_guide_for_task(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.generate_guide()

    def run_task_outside_schedule(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        task.run_outside_schedule()

        with self.update_wait_cond:
            self.update_wait_cond.notify_all()

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
