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

from openscap_daemon.task import Task
from openscap_daemon.config import Configuration
from openscap_daemon import oscap_helpers
from openscap_daemon import async


class ResultsNotAvailable(Exception):
    def __init__(self):
        super(ResultsNotAvailable, self).__init__()


EVALUATION_PRIORITY = 0
TASK_ACTION_PRIORITY = 10


class System(object):
    def __init__(self, config_file):
        self.async = async.AsyncManager()

        logging.info("Loading configuration from '%s'.", config_file)
        self.config = Configuration()
        self.config.load(config_file)
        self.config.autodetect_tool_paths()
        self.config.autodetect_content_paths()
        self.config.prepare_dirs()

        self.async_eval_spec_results = dict()
        self.async_eval_spec_results_lock = threading.Lock()

        self.tasks = dict()
        self.tasks_lock = threading.Lock()
        # a set of tasks that have already been scheduled, we keep this so that
        # we don't schedule a task twice in a row
        self.tasks_scheduled = set()

        self.update_wait_cond = threading.Condition()

        self.async_eval_cve_scanner_worker_results = dict()
        self.async_eval_cve_scanner_worker_results_lock = threading.Lock()

    def get_ssg_choices(self):
        ret = []
        if self.config.ssg_path == "":
            return ret

        for ssg_file in os.listdir(self.config.ssg_path):
            full_path = os.path.join(self.config.ssg_path, ssg_file)

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

    class AsyncEvaluateSpecAction(async.AsyncAction):
        def __init__(self, system, spec):
            super(System.AsyncEvaluateSpecAction, self).__init__()

            self.system = system
            self.spec = spec

        def run(self):
            arf, stdout, stderr, exit_code = \
                self.spec.evaluate(self.system.config)

            with self.system.async_eval_spec_results_lock:
                self.system.async_eval_spec_results[self.token] = \
                    (arf, stdout, stderr, exit_code)

        def __str__(self):
            return "Evaluate Spec '%s'" % (self.spec)

    def evaluate_spec_async(self, spec):
        return self.async.enqueue(
            System.AsyncEvaluateSpecAction(
                self,
                spec
            ),
            EVALUATION_PRIORITY
        )

    def get_evaluate_spec_async_results(self, token):
        with self.async_eval_spec_results_lock:
            if token not in self.async_eval_spec_results:
                raise ResultsNotAvailable()

            arf, stdout, stderr, exit_code = self.async_eval_spec_results[token]
            del self.async_eval_spec_results[token]

        return arf, stdout, stderr, exit_code

    def load_tasks(self):
        logging.info("Loading task definitions from '%s'...",
                     self.config.tasks_dir)
        task_files = os.listdir(self.config.tasks_dir)

        task_count = 0
        for task_file in task_files:
            if not task_file.endswith(".xml"):
                logging.warning(
                    "Found '%s' in task definitions directory '%s'. Paths "
                    "not ending with '.xml' are unexpected in the task "
                    "definitions directory ", task_file, self.config.tasks_dir
                )
                continue

            full_path = os.path.join(self.config.tasks_dir, task_file)

            if not os.path.isfile(full_path):
                logging.warning(
                    "Found '%s' in task definitions directory '%s'. This path "
                    "is not a file. Only files are expected in the task "
                    "definitions directory ", full_path, self.config.tasks_dir
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
            "Successfully loaded %i task definitions.", task_count
        )

    def save_tasks(self):
        logging.info("Saving task definitions to '%s'...",
                     self.config.tasks_dir)
        task_count = 0
        with self.tasks_lock:
            for _, task in self.tasks.items():
                task.save()
                task_count += 1

        logging.info(
            "Successfully saved %i task definitions.", task_count
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
                self.config.tasks_dir, "%i.xml" % (task_id)
            )

            self.tasks[task_id] = task

            # We do not save the task on purpose, empty tasks are worthless.
            # The task will be saved to disk as soon as one of its properties is
            # set.
            # task.save()

            logging.info("Created a new empty task with ID '%i'.", task_id)

            # Do not notify the update_wait_cond, the task is disabled so it
            # doesn't affect the schedule in any way

            # with self.update_wait_cond:
            #    self.update_wait_cond.notify_all()

        return task_id

    def remove_task(self, task_id, remove_results):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]
            if task.enabled:
                raise RuntimeError(
                    "Can't remove enabled task '%i'. Please disable it first." %
                    (task_id)
                )

            if not remove_results:
                result_ids = task.list_result_ids(self.config.results_dir)
                if len(result_ids) > 0:
                    raise RuntimeError(
                        "Can't remove task '%i', in has %i results stored. "
                        "Please remove all the results first." %
                        (task_id, len(result_ids))
                    )
            else:
                logging.debug("Remove task results before.")
                task.remove_results(self.config)
            del self.tasks[task_id]

        os.remove(self._get_task_file_path(task_id))
        logging.info("Removed task '%i'.", task_id)

    def _get_task_file_path(self, task_id):
        return os.path.join(self.config.tasks_dir, "%i.xml" % (task_id))

    def remove_task_results(self, task_id):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.remove_results(self.config)

    def remove_task_result(self, task_id, result_id):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.remove_result(result_id, self.config)

    def set_task_enabled(self, task_id, enabled):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.enabled = bool(enabled)
            task.save()

        logging.info(
            "%s task with ID %i.",
            "Enabled" if enabled else "Disabled", task_id
        )

        if task.enabled:
            with self.update_wait_cond:
                self.update_wait_cond.notify_all()

    def get_task_enabled(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.enabled

    def set_task_title(self, task_id, title):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.title = title
            task.save()

        logging.info("Set title of task with ID %i to '%s'.", task_id, title)

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
            task.evaluation_spec.target = target
            task.save()

        logging.info("Set target of task with ID %i to '%s'.", task_id, target)

    def get_task_target(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.evaluation_spec.target

    def get_task_created_timestamp(self, task_id):
        task_path = self._get_task_file_path(task_id)
        return os.path.getctime(task_path)

    def get_task_modified_timestamp(self, task_id):
        task_path = self._get_task_file_path(task_id)
        return os.path.getmtime(task_path)

    def set_task_input(self, task_id, input_):
        """input can be an absolute file path or the XML source itself. This is
        autodetected.
        """

        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            if input_ is None or os.path.isabs(input_):
                task.evaluation_spec.input_.set_file_path(input_)

                logging.info(
                    "Set input content of task with ID %i to file '%s'.",
                    task_id, input_
                )

            else:
                task.evaluation_spec.input_.set_contents(input_)

                logging.info(
                    "Set input content of task with ID %i to custom XML.",
                    task_id
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
                task.evaluation_spec.tailoring.set_file_path(tailoring)

                logging.info(
                    "Set tailoring content of task with ID %i to file '%s'.",
                    task_id, tailoring
                )

            else:
                task.evaluation_spec.tailoring.set_contents(tailoring)

                logging.info(
                    "Set tailoring content of task with ID %i to custom XML.",
                    task_id
                )

            task.save()

    def set_task_profile_id(self, task_id, profile_id):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.evaluation_spec.profile_id = profile_id
            task.save()

        logging.info(
            "Set profile ID of task with ID %i to '%s'.", task_id, profile_id
        )

    def set_task_online_remediation(self, task_id, remediation_enabled):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.evaluation_spec.online_remediation = bool(remediation_enabled)
            task.save()

        logging.info(
            "%s online remediation of task with ID %i.",
            "Enabled" if remediation_enabled else "Disabled", task_id
        )

    def set_task_schedule_not_before(self, task_id, schedule_not_before):
        task = None

        with self.tasks_lock:
            task = self.tasks[task_id]

        with task.update_lock:
            task.schedule.not_before = schedule_not_before
            task.save()

        logging.info(
            "Set schedule not before of task with ID %i to %s.",
            task_id, schedule_not_before
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
            "Set schedule repeat after of task with ID %i to %s.",
            task_id, schedule_repeat_after
        )

        # This changes the schedule which potentially obsoletes the precomputed
        # schedule. Make sure we re-schedule everything.
        if task.enabled:
            with self.update_wait_cond:
                self.update_wait_cond.notify_all()

    def get_closest_datetime(self, reference_datetime):
        ret = None

        with self.tasks_lock:
            for task in self.tasks.values():
                if task.id_ in self.tasks_scheduled:
                    continue

                next_update_time = task.get_next_update_time(reference_datetime)
                if next_update_time is None:
                    continue

                if ret is None or next_update_time < ret:
                    ret = next_update_time

        return ret

    class AsyncUpdateTaskAction(async.AsyncAction):
        def __init__(self, system, task_id, reference_datetime):
            super(System.AsyncUpdateTaskAction, self).__init__()

            self.system = system
            self.task_id = task_id
            self.reference_datetime = reference_datetime

        def run(self):
            task = None
            with self.system.tasks_lock:
                task = self.system.tasks[self.task_id]

            task.update(self.reference_datetime, self.system.config)

            with self.system.tasks_lock:
                self.system.tasks_scheduled.remove(task.id_)

        def __str__(self):
            return "Update Task '%i' with reference_datetime='%s'" \
                   % (self.task_id, self.reference_datetime)

    def schedule_tasks(self, reference_datetime=None):
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
            "Scheduling task updates, reference_datetime='%s'.",
            str(reference_datetime)
        )

        with self.tasks_lock:
            for task in self.tasks.values():
                if task.id_ in self.tasks_scheduled:
                    continue

                if task.should_be_updated(reference_datetime):
                    self.tasks_scheduled.add(task.id_)
                    self.async.enqueue(
                        System.AsyncUpdateTaskAction(
                            self,
                            task.id_,
                            reference_datetime
                        ),
                        TASK_ACTION_PRIORITY
                    )

    def schedule_tasks_worker(self):
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
                            "Interruptible if task specs change.", time_to_wait
                        )
                        self.update_wait_cond.wait(seconds_to_wait)

            self.schedule_tasks(reference_datetime)

    def generate_guide_for_task(self, task_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.evaluation_spec.generate_guide(self.config)

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
        return task.list_result_ids(self.config.results_dir)

    def get_task_result_created_timestamp(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_result_created_timestamp(result_id, self.config)

    def get_xml_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_xml_of_result(result_id, self.config)

    def get_stdout_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_stdout_of_result(result_id, self.config)

    def get_stderr_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_stderr_of_result(result_id, self.config)

    def get_exit_code_of_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.get_exit_code_of_result(result_id, self.config)

    def generate_report_for_task_result(self, task_id, result_id):
        task = None
        with self.tasks_lock:
            task = self.tasks[task_id]

        return task.generate_report_for_result(
            result_id,
            self.config
        )

    class AsyncEvaluateCVEScannerWorkerAction(async.AsyncAction):
        def __init__(self, system, worker):
            super(System.AsyncEvaluateCVEScannerWorkerAction, self).__init__()

            self.system = system
            self.worker = worker

        def run(self):
            json_result = self.worker.start_application()

            with self.system.async_eval_cve_scanner_worker_results_lock:
                self.system.async_eval_cve_scanner_worker_results[self.token] = \
                    json_result

        def __str__(self):
            return "Evaluate CVE Scanner Worker '%s'" % (self.worker)

    def evaluate_cve_scanner_worker_async(self, worker):
        return self.async.enqueue(
            System.AsyncEvaluateCVEScannerWorkerAction(
                self,
                worker
            ),
            EVALUATION_PRIORITY
        )

    def get_evaluate_cve_scanner_worker_async_results(self, token):
        with self.async_eval_cve_scanner_worker_results_lock:
            if token not in self.async_eval_cve_scanner_worker_results:
                raise ResultsNotAvailable()

            json_results = self.async_eval_cve_scanner_worker_results[token]
            del self.async_eval_cve_scanner_worker_results[token]

        return json_results
