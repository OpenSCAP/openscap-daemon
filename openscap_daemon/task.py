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


from openscap_daemon import et_helpers
from openscap_daemon import oscap_helpers
from openscap_daemon import evaluation_spec

from xml.etree import cElementTree as ElementTree
from datetime import datetime, timedelta
import os.path
import shutil
import threading
import logging
import tempfile


class SlipMode(object):
    """This enum describes how to behave when scheduling repeated tasks.

    Consider task 1 which is scheduled to run hourly every hour. Last run was
    at 23:00. Schedule is to run 0:00, 1:00, 2:00, ... After last run, the
    machine was turned off for 3 hours. Time is now 2:05.

    With no_slip we will run 3 evaluations and the next schedule is 4:00.
    With slip_missed we will run 1 evaluation and the next schedule is 4:05.
    With slip_missed_aligned we will run 1 evaluation the next schedule is 4:00.

    The de-facto standard is drop_missed_aligned. The tools will try their best
    to be right on the timetable. In case of misses they will run one task ASAP
    and try to adhere precisely to the timetable again.
    """

    UNKNOWN = 0
    NO_SLIP = 1
    DROP_MISSED = 2
    DROP_MISSED_ALIGNED = 3

    @staticmethod
    def from_string(slip_mode):
        if slip_mode == "no_slip":
            return SlipMode.NO_SLIP
        elif slip_mode == "drop_missed":
            return SlipMode.DROP_MISSED
        elif slip_mode == "drop_missed_aligned":
            return SlipMode.DROP_MISSED_ALIGNED

        return SlipMode.UNKNOWN

    @staticmethod
    def to_string(slip_mode):
        if slip_mode == SlipMode.NO_SLIP:
            return "no_slip"
        elif slip_mode == SlipMode.DROP_MISSED:
            return "drop_missed"
        elif slip_mode == SlipMode.DROP_MISSED_ALIGNED:
            return "drop_missed_aligned"

        return "unknown"


class Schedule(object):
    def __init__(self):
        self.not_before = None
        self.repeat_after = 0
        self.slip_mode = SlipMode.DROP_MISSED_ALIGNED

    def is_equivalent_to(self, other):
        return \
            self.not_before == other.not_before and \
            self.repeat_after == other.repeat_after and \
            self.slip_mode == other.slip_mode

    def load_from_xml_element(self, element):
        schedule_not_before_attr = element.get("not_before")

        # we expect UTC, no timezone shifts
        if schedule_not_before_attr is not None:
            self.not_before = datetime.strptime(
                schedule_not_before_attr,
                "%Y-%m-%dT%H:%M"
            )
        else:
            self.not_before = None

        schedule_repeat_after_attr = element.get("repeat_after")

        if schedule_repeat_after_attr is not None:
            self.repeat_after = int(schedule_repeat_after_attr)
        else:
            self.repeat_after = None

        self.slip_mode = SlipMode.from_string(
            element.get("slip_mode", "drop_missed_aligned")
        )

    def to_xml_element(self):
        ret = ElementTree.Element("schedule")
        if self.not_before is not None:
            ret.set("not_before", self.not_before.strftime("%Y-%m-%dT%H:%M"))

        ret.set("repeat_after", str(self.repeat_after))
        ret.set("slip_mode", SlipMode.to_string(self.slip_mode))

        return ret

    def next_not_before(self, reference_datetime):
        """Calculates the next schedule_not_before based on
        schedule_repeat_after and schedule_slip_mode.
        """

        if self.not_before is None:
            # the task is already disabled, no need to schedule next run
            return None

        if self.repeat_after is None:
            # task repetition is disabled
            return None

        if self.slip_mode == SlipMode.NO_SLIP:
            return self.not_before + timedelta(hours=self.repeat_after)

        elif self.slip_mode == SlipMode.DROP_MISSED:
            return reference_datetime + timedelta(hours=self.repeat_after)

        elif self.slip_mode == SlipMode.DROP_MISSED_ALIGNED:
            candidate = self.not_before + timedelta(hours=self.repeat_after)

            while candidate <= reference_datetime:
                candidate += timedelta(hours=self.repeat_after)

            return candidate

        else:
            raise RuntimeError("Unrecognized slip_mode.")


class Task(object):
    """This class defined input content, tailoring, profile, ..., and schedule
    for an SCAP evaluation task.

    Example of a task:
        Run USGCB evaluation on RHEL6 localhost machine, every day at 1:00.

    Task is composed of EvaluationSpec and Schedule
    """

    def __init__(self):
        self.id_ = None
        self.config_file = None
        self.enabled = False

        self.title = None
        self.evaluation_spec = evaluation_spec.EvaluationSpec()

        self.schedule = Schedule()
        # If True, this task will be evaluated once without affecting the
        # schedule. This feature is important for test runs. This variable does
        # not persist because it is not saved to the config file!
        self.run_outside_schedule_once = False

        # Prevents multiple updates of the same task running
        self.update_lock = threading.Lock()

    def __str__(self):
        ret = "Task from config file '%s' with:\n" % (self.config_file)
        ret += "- ID: \t%i\n" % (self.id_)
        ret += "- title: \t%s\n" % (self.title)
        ret += str(self.evaluation_spec) + "\n"
        ret += "- schedule:\n"
        ret += "  - not before: \t%s\n" % (self.schedule.not_before)
        ret += "  - repeat after: \t%s\n" % (self.schedule.repeat_after)
        ret += "  - slip mode: \t%s\n" %\
               (SlipMode.to_string(self.schedule.slip_mode))

        return ret

    def is_valid(self):
        if not self.evaluation_spec.is_valid():
            return False

        return True

    def is_equivalent_to(self, other):
        """Checks that both "Task self" and "Task other" are the same except for
        id_ and config_file.
        """

        return \
            self.evaluation_spec.is_equivalent_to(other.evaluation_spec) and \
            self.title == other.title and \
            self.schedule.is_equivalent_to(other.schedule) and \
            self.run_outside_schedule_once == other.run_outside_schedule_once

    @staticmethod
    def get_task_id_from_filepath(filepath):
        filename, extension = os.path.splitext(
            os.path.basename(filepath)
        )

        ret = int(filename)
        assert(ret > 0)
        return ret

    def load_from_xml_element(self, root, config_file):
        self.id_ = Task.get_task_id_from_filepath(config_file)
        self.enabled = root.get("enabled", "false") == "true"

        self.title = et_helpers.get_element_text(root, "title")

        self.evaluation_spec = evaluation_spec.EvaluationSpec()
        self.evaluation_spec.load_from_xml_element(
            et_helpers.get_element(root, "evaluation_spec")
        )

        self.schedule = Schedule()
        self.schedule.load_from_xml_element(
            et_helpers.get_element(root, "schedule")
        )

        self.config_file = config_file

    def load(self, config_file):
        tree = ElementTree.parse(config_file)
        root = tree.getroot()
        self.load_from_xml_element(root, config_file)

    def reload(self):
        if self.config_file is not None:
            raise RuntimeError("Can't reload, config_file is not set.")

        self.load(self.config_file)

    def to_xml_element(self):
        root = ElementTree.Element("task")
        root.set("enabled", "true" if self.enabled else "false")

        if self.title is not None:
            title_element = ElementTree.Element("title")
            title_element.text = self.title
            root.append(title_element)

        evaluation_spec_element = self.evaluation_spec.to_xml_element()
        root.append(evaluation_spec_element)

        schedule_element = self.schedule.to_xml_element()
        root.append(schedule_element)

        return root

    def save_as(self, config_file):
        root = self.to_xml_element()
        et_helpers.indent(root)

        xml_source = ElementTree.tostring(root, encoding="utf-8")
        with open(config_file, "w") as f:
            f.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
            f.write(xml_source)

    def save(self):
        assert(self.config_file is not None)
        self.save_as(self.config_file)

    def next_schedule_not_before(self, reference_datetime):
        # TODO: Get rid of this delegate
        return self.schedule.next_not_before(reference_datetime)

    def _get_task_results_dir(self, results_dir):
        ret = os.path.join(results_dir, str(self.id_))
        if not os.path.exists(ret):
            os.mkdir(ret)

        return ret

    def list_result_ids(self, results_dir):
        """IDs are returned in reverse order sorted by strings as if they were
        integers.

        for example: ['10', '9', '8', '1']
        """

        # The lambda is there to make sure we don't consider 2 "larger"
        # than 10. For example to avoid sorted lists such as:
        # ['9', '8', '10', '1'] where we wanted ['10', '9', '8', '1']

        return sorted(
            os.listdir(self._get_task_results_dir(results_dir)), reverse=True,
            key=lambda s: (len(s), s)
        )

    def _get_next_target_dir(self, results_dir):
        # We may consider having a file that contains the last ID in the
        # future. I considered that but right now I think a result with more
        # than a few thousand results is unlikely. User will use results
        # purging. Sorting a couple thousand results is still very quick.
        # Having a file with the last ID makes this operation O(1) instead
        # of O(n*log(n)).

        # result_ids are guaranteed to be reverse sorted by int
        result_ids = self.list_result_ids(results_dir)

        last = 0
        for last_candidate in result_ids:
            try:
                last = int(last_candidate)
                break
            except:
                pass

        ret = os.path.join(
            self._get_task_results_dir(results_dir),
            str(last + 1)
        )
        assert(not os.path.exists(ret))
        return ret

    def get_next_update_time(self, reference_datetime, log=False):
        if not self.enabled:
            if log:
                logging.debug(
                    "Task '%i' is disabled, not updating it." %
                    (self.id_)
                )
            return None

        if self.run_outside_schedule_once:
            if log:
                logging.debug(
                    "Evaluating task '%i'. It was set to be run once outside "
                    "its schedule." %
                    (self.id_)
                )
            return reference_datetime

        if self.schedule.not_before is None:
            if log:
                logging.debug(
                    "Task '%i' is enabled but schedule.not_before is None. "
                    "It won't be run automatically." %
                    (self.id_)
                )

        return self.schedule.not_before

    def should_be_updated(self, reference_datetime, log=False):
        next_update_time = self.get_next_update_time(reference_datetime, log)
        if next_update_time is not None and \
           next_update_time <= reference_datetime:
            if log:
                logging.debug(
                    "Evaluating task '%i'. It was scheduled to be "
                    "evaluated later than %s, reference_datetime %s is "
                    "higher than or equal." %
                    (self.id_, next_update_time, reference_datetime)
                )

            return True

        return False

    def update(self, reference_datetime, config):
        """Figures out if the task should be run right now, alters the schedule
        values accordingly.

        reference datetime is passed mainly because of easier diagnostics.
        It prevents some tasks being run and others not even though they have
        the same not_before value.

        Assumption: tick is never in parallel on the same Task. It can be run
        in parallel on different tasks but at most once for 1 Task instance.
        """

        with self.update_lock:
            if not self.is_valid():
                raise RuntimeError("Can't update an invalid Task.")

            if self.should_be_updated(reference_datetime, True):
                wip_result = self.evaluation_spec.evaluate_into_dir(config)

                # We already have update_lock, there is no risk of a race
                # condition between acquiring target dir and moving the results
                # there.
                target_dir = self._get_next_target_dir(config.results_dir)
                logging.debug(
                    "Moving results of task '%s' from '%s' to '%s'." %
                    (self.id_, wip_result, target_dir)
                )

                shutil.move(wip_result, target_dir)
                logging.info(
                    "Evaluated task '%s', new result in '%s'." %
                    (self.id_, target_dir)
                )

                if not self.run_outside_schedule_once:
                    self.schedule.not_before = \
                        self.schedule.next_not_before(reference_datetime)

                    self.save()

                else:
                    self.run_outside_schedule_once = False

    def generate_guide(self, config):
        return self.evaluation_spec.generate_guide(config)

    def run_outside_schedule(self):
        if not self.enabled:
            raise RuntimeError(
                "This task is disabled. Enable it first if you want to run it "
                "once outside the schedule!"
            )

        if self.run_outside_schedule_once:
            raise RuntimeError(
                "This task was already scheduled to be run once "
                "outside the schedule!"
            )

        self.run_outside_schedule_once = True

        logging.info(
            "Set task '%i' to be run once outside the schedule." %
            (self.id_)
        )

    def get_arf_of_result(self, result_id, config):
        # TODO: This needs refactoring in the future, the secret that the file
        #       is called "arf.xml" is all over the place.
        path = os.path.join(
            self._get_task_results_dir(config.results_dir),
            str(result_id),
            "arf.xml"
        )

        logging.debug(
            "Retrieving ARF of result '%i' of task '%i', expected path '%s'." %
            (result_id, self.id_, path)
        )

        ret = ""
        with open(path, "r") as f:
            ret = f.read().decode("utf-8")

        logging.info(
            "Retrieved ARF of result '%i' of task '%i'." %
            (result_id, self.id_)
        )

        return ret

    def get_stdout_of_result(self, result_id, config):
        path = os.path.join(
            self._get_task_results_dir(config.results_dir),
            str(result_id),
            "stderr"
        )

        ret = ""
        with open(path, "r") as f:
            ret = f.read()

        return ret

    def get_stderr_of_result(self, result_id, config):
        path = os.path.join(
            self._get_task_results_dir(config.results_dir),
            str(result_id),
            "stderr"
        )

        ret = ""
        with open(path, "r") as f:
            ret = f.read()

        return ret

    def get_exit_code_of_result(self, result_id, config):
        path = os.path.join(
            self._get_task_results_dir(config.results_dir),
            str(result_id),
            "exit_code"
        )

        ret = ""
        with open(path, "r") as f:
            ret = f.read()

        return int(ret.strip())

    def generate_report_for_result(self, result_id, config):
        return oscap_helpers.generate_report_for_result(
            self.evaluation_spec,
            self._get_task_results_dir(config.results_dir),
            result_id,
            config
        )
