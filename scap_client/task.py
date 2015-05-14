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


from scap_client import et_helpers
from scap_client import oscap_helpers

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


class Task(object):
    """This class defined input content, tailoring, profile, ..., and schedule
    for an SCAP evaluation task.

    Example of a task:
        Run USGCB evaluation on RHEL6 localhost machine, every day at 1:00.
    """

    def __init__(self):
        self.id_ = None
        self.config_file = None

        self.title = None
        self.target = "localhost"
        self.input_file = None
        self.input_temp_file = None
        self.input_datastream_id = None
        self.input_xccdf_id = None
        self.tailoring_file = None
        self.tailoring_temp_file = None
        self.profile_id = None
        self.online_remediation = False
        self.schedule_not_before = None
        self.schedule_repeat_after = 0
        self.schedule_slip_mode = SlipMode.DROP_MISSED_ALIGNED

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
        ret += "- target: \t%s\n" % (self.target)
        ret += "- input:\n"
        ret += "  - file: \t%s\n" % (self.input_file)
        if self.input_temp_file is not None:
            ret += "    - bundled"
        ret += "  - datastream_id: \t%s\n" % (self.input_datastream_id)
        ret += "  - xccdf_id: \t%s\n" % (self.input_xccdf_id)
        ret += "  - tailoring file: \t%s\n" % (self.tailoring_file)
        if self.tailoring_temp_file is not None:
            ret += "    - bundled"
        ret += "- profile ID: \t%s\n" % (self.profile_id)
        ret += "- online remediation: \t%s\n" % \
            ("enabled" if self.online_remediation else "disabled")
        ret += "- schedule:\n"
        ret += "  - not before: \t%s\n" % (self.schedule_not_before)
        ret += "  - repeat after: \t%s\n" % (self.schedule_repeat_after)
        ret += "  - slip mode: \t%s\n" % (self.schedule_slip_mode)

        return ret

    def is_valid(self):
        if self.input_file is None:
            return False

        if self.target is None:
            return False

        return True

    def is_equivalent_to(self, other):
        """Checks that both "Task self" and "Task other" are the same except for
        id_ and config_file.
        """

        # TODO input_file and tailoring_file may have the same contents and
        # different paths and the tasks wouldn't end up being equivalent.

        return \
            self.title == other.title and \
            self.target == other.target and \
            self.input_file == other.input_file and \
            self.input_datastream_id == other.input_datastream_id and \
            self.input_xccdf_id == other.input_xccdf_id and \
            self.tailoring_file == other.tailoring_file and \
            self.profile_id == other.profile_id and \
            self.online_remediation == other.online_remediation and \
            self.schedule_not_before == other.schedule_not_before and \
            self.schedule_repeat_after == other.schedule_repeat_after and \
            self.schedule_slip_mode == other.schedule_slip_mode

    @staticmethod
    def get_task_id_from_filepath(filepath):
        filename, extension = os.path.splitext(
            os.path.basename(filepath)
        )

        ret = int(filename)
        assert(ret > 0)
        return ret

    def set_input_file(self, file_path):
        self.input_temp_file = None
        if file_path is not None:
            self.input_file = \
                os.path.abspath(file_path) if file_path is not None else None

        else:
            self.input_file = None

    def set_input_contents(self, input_contents):
        if input_contents is not None:
            self.input_temp_file = tempfile.NamedTemporaryFile()
            self.input_temp_file.write(input_contents.encode("utf-8"))
            self.input_temp_file.flush()

            self.input_file = os.path.abspath(self.input_temp_file.name)

        else:
            self.input_file = None

    def set_tailoring_file(self, file_path):
        self.tailoring_temp_file = None
        self.tailoring_file = \
            os.path.abspath(file_path) if file_path is not None else None

    def set_tailoring_contents(self, tailoring_contents):
        if tailoring_contents is not None:
            self.tailoring_temp_file = tempfile.NamedTemporaryFile()
            self.tailoring_temp_file.write(tailoring_contents.encode("utf-8"))
            self.tailoring_temp_file.flush()

            self.tailoring_file = os.path.abspath(self.tailoring_temp_file.name)

        else:
            self.tailoring_file = None

    def load_from_xml_element(self, root, config_file):
        self.id_ = Task.get_task_id_from_filepath(config_file)
        self.title = et_helpers.get_element_text(root, "title")

        self.target = et_helpers.get_element_text(root, "target")

        input_file = et_helpers.get_element_attr(root, "input", "href")
        if input_file is not None:
            self.set_input_file(input_file)

        else:
            input_file_contents = et_helpers.get_element_text(root, "input")
            self.set_input_contents(input_file_contents)

        self.input_datastream_id = \
            et_helpers.get_element_attr(root, "input", "datastream_id")
        self.input_xccdf_id = \
            et_helpers.get_element_attr(root, "input", "xccdf_id")

        # TODO: in the future we want datastream tailoring as well
        tailoring_file = \
            et_helpers.get_element_attr(root, "tailoring", "href")
        if tailoring_file is not None:
            self.set_tailoring_file(tailoring_file)

        else:
            tailoring_file_contents = \
                et_helpers.get_element_text(root, "tailoring")
            self.set_tailoring_contents(tailoring_file_contents)

        self.profile_id = et_helpers.get_element_text(root, "profile")
        self.online_remediation = \
            et_helpers.get_element_text(root, "online_remediation") == "true"

        schedule_not_before_attr = et_helpers.get_element_attr(
            root, "schedule", "not_before")

        # we expect UTC, no timezone shifts
        if schedule_not_before_attr is not None:
            self.schedule_not_before = datetime.strptime(
                schedule_not_before_attr,
                "%Y-%m-%dT%H:%M"
            )
        else:
            self.schedule_not_before = None

        schedule_repeat_after_attr = et_helpers.get_element_attr(
            root, "schedule", "repeat_after")

        if schedule_repeat_after_attr is not None:
            self.schedule_repeat_after = int(schedule_repeat_after_attr)
        else:
            self.schedule_repeat_after = None

        self.schedule_slip_mode = SlipMode.from_string(
            et_helpers.get_element_attr(
                root, "schedule", "slip_mode", "drop_missed_aligned")
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

        if self.title is not None:
            title_element = ElementTree.Element("title")
            title_element.text = self.title
            root.append(title_element)

        target_element = ElementTree.Element("target")
        target_element.text = self.target
        root.append(target_element)

        if self.input_file is not None:
            input_element = ElementTree.Element("input")
            if self.input_temp_file is None:
                input_element.set("href", self.input_file)
            else:
                with open(self.input_temp_file.name, "r") as f:
                    input_element.text = f.read().decode("utf-8")

            if self.input_datastream_id is not None:
                input_element.set("datastream_id", self.input_datastream_id)
            if self.input_xccdf_id is not None:
                input_element.set("xccdf_id", self.input_xccdf_id)
            root.append(input_element)

        if self.tailoring_file is not None:
            tailoring_element = ElementTree.Element("tailoring")

            if self.tailoring_temp_file is None:
                tailoring_element.set("href", self.tailoring_file)
            else:
                with open(self.tailoring_temp_file.name, "r") as f:
                    tailoring_element.text = f.read().decode("utf-8")

            root.append(tailoring_element)

        if self.profile_id is not None:
            profile_element = ElementTree.Element("profile")
            profile_element.text = self.profile_id
            root.append(profile_element)

        online_remediation_element = ElementTree.Element("online_remediation")
        online_remediation_element.text = \
            "true" if self.online_remediation else "false"
        root.append(online_remediation_element)

        schedule_element = ElementTree.Element("schedule")
        if self.schedule_not_before is not None:
            schedule_element.set(
                "not_before",
                self.schedule_not_before.strftime("%Y-%m-%dT%H:%M")
            )

        schedule_element.set("repeat_after",
                             str(self.schedule_repeat_after))
        schedule_element.set("slip_mode",
                             SlipMode.to_string(self.schedule_slip_mode))
        root.append(schedule_element)

        # TODO: Maybe move this to save_as? Is there value in returning an
        # indented element from this method?
        et_helpers.indent(root)

        return root

    def save_as(self, config_file):
        root = self.to_xml_element()
        xml_source = ElementTree.tostring(root, encoding="utf-8")
        with open(config_file, "w") as f:
            f.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
            f.write(xml_source)

    def save(self):
        assert(self.config_file is not None)
        self.save_as(self.config_file)

    def next_schedule_not_before(self, reference_datetime):
        """Calculates the next schedule_not_before based on
        schedule_repeat_after and schedule_slip_mode.
        """

        if self.schedule_not_before is None:
            # the task is already disabled, no need to schedule next run
            return None

        if self.schedule_repeat_after is None:
            # task repetition is disabled
            return None

        if self.schedule_slip_mode == SlipMode.NO_SLIP:
            return self.schedule_not_before + \
                timedelta(hours=self.schedule_repeat_after)

        elif self.schedule_slip_mode == SlipMode.DROP_MISSED:
            return reference_datetime + \
                timedelta(hours=self.schedule_repeat_after)

        elif self.schedule_slip_mode == SlipMode.DROP_MISSED_ALIGNED:
            candidate = self.schedule_not_before + \
                timedelta(hours=self.schedule_repeat_after)

            while candidate <= reference_datetime:
                candidate += timedelta(hours=self.schedule_repeat_after)

            return candidate

        else:
            raise RuntimeError("Unrecognized schedule_slip_mode.")

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

    def get_next_update_time(self, reference_datetime):
        if self.run_outside_schedule_once:
            return reference_datetime

        return self.schedule_not_before

    def update(self, reference_datetime, results_dir,
               work_in_progress_results_dir):
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
                raise RuntimeError("Can't tick an invalid Task.")

            update_now = False

            if not self.run_outside_schedule_once:
                # This functionality is replicated in get_next_update_time,
                # it would be great to refactor this and only do it once but
                # then we would lose the logging...

                if self.schedule_not_before is None:
                    # this Task is not scheduled to run right now,
                    # it is disabled
                    logging.debug(
                        "Task '%s' is disabled. schedule_not_before is None." %
                        (self.id_)
                    )

                elif self.schedule_not_before <= reference_datetime:
                    logging.debug(
                        "Evaluating task '%s'. It was scheduled to be "
                        "evaluated later than %s, reference_datetime %s is "
                        "higher than or equal." %
                        (self.id_, self.schedule_not_before, reference_datetime)
                    )
                    update_now = True

            else:
                logging.debug(
                    "Evaluating task '%s'. It was set to be run once outside "
                    "its schedule." %
                    (self.id_)
                )

                # This task is scheduled to run once ignoring the schedule
                update_now = True

            if update_now:
                wip_result = oscap_helpers.evaluate_task(
                    self, work_in_progress_results_dir)

                # We already have update_lock, there is no risk of a race
                # condition between acquiring target dir and moving the results
                # there.
                target_dir = self._get_next_target_dir(results_dir)
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
                    self.schedule_not_before = \
                        self.next_schedule_not_before(reference_datetime)

                    self.save()

                else:
                    self.run_outside_schedule_once = False

    def generate_guide(self):
        return oscap_helpers.generate_guide_for_task(self)

    def run_outside_schedule(self):
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

    def get_arf_of_result(self, results_dir, result_id):
        # TODO: This needs refactoring in the future, the secret that the file
        #       is called "arf.xml" is all over the place.
        path = os.path.join(
            results_dir, str(self.id_), str(result_id), "arf.xml"
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

    def get_stdout_of_result(self, results_dir, result_id):
        path = os.path.join(
            results_dir, str(self.id_), str(result_id), "stdout"
        )
        ret = ""
        with open(path, "r") as f:
            ret = f.read()

        return ret

    def get_stderr_of_result(self, results_dir, result_id):
        path = os.path.join(
            results_dir, str(self.id_), str(result_id), "stderr"
        )
        ret = ""
        with open(path, "r") as f:
            ret = f.read()

        return ret

    def get_exit_code_of_result(self, results_dir, result_id):
        path = os.path.join(
            results_dir, str(self.id_), str(result_id), "exit_code"
        )
        ret = ""
        with open(path, "r") as f:
            ret = f.read()

        return int(ret.strip())

    def generate_report_for_result(self, results_dir, result_id):
        return oscap_helpers.generate_report_for_result(
            self,
            os.path.join(results_dir, str(self.id_)),
            result_id
        )
