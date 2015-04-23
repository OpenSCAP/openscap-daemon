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


from scap_client.et_helpers import get_element_attr, get_element_text
from scap_client import oscap_helpers

from xml.etree import cElementTree as ElementTree
from datetime import datetime, timedelta
import os.path
import shutil


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
        self.input_file = None
        self.input_datastream_id = None
        self.input_xccdf_id = None
        self.tailoring_file = None
        self.profile_id = None
        self.online_remediation = False
        self.target = None
        self.schedule_not_before = None
        self.schedule_repeat_after = None
        self.schedule_slip_mode = SlipMode.DROP_MISSED_ALIGNED

    def __str__(self):
        ret = "Task from config file '%s' with:\n" % (self.config_file)
        ret += "- ID: \t%s\n" % (self.id_)
        ret += "- title: \t%s\n" % (self.title)
        ret += "- input:\n"
        ret += "  - file: \t%s\n" % (self.input_file)
        ret += "  - datastream_id: \t%s\n" % (self.input_datastream_id)
        ret += "  - xccdf_id: \t%s\n" % (self.input_xccdf_id)
        ret += "- tailoring file: \t%s\n" % (self.tailoring_file)
        ret += "- profile ID: \t%s\n" % (self.profile_id)
        ret += "- online remediation: \t%s\n" % \
            ("enabled" if self.online_remediation else "disabled")
        ret += "- target: \t%s\n" % (self.target)
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

    def load(self, config_file):
        try:
            tree = ElementTree.parse(config_file)
            root = tree.getroot()

            filename, extension = os.path.splitext(
                os.path.basename(config_file)
            )
            self.id_ = filename
            self.title = get_element_text(root, "title")
            self.input_file = get_element_attr(root, "input", "href")
            self.input_datastream_id = \
                get_element_attr(root, "input", "datastream_id")
            self.input_xccdf_id = \
                get_element_attr(root, "input", "xccdf_id")
            # TODO: in the future we want datastream tailoring as well
            self.tailoring_file = get_element_attr(root, "tailoring", "href")
            self.profile_id = get_element_text(root, "profile")
            self.online_remediation = \
                get_element_text(root, "online_remediation") == "true"
            self.target = get_element_text(root, "target")

            schedule_not_before_attr = get_element_attr(
                root, "schedule", "not_before")

            # we expect UTC, no timezone shifts
            if schedule_not_before_attr is not None:
                self.schedule_not_before = datetime.strptime(
                    schedule_not_before_attr,
                    "%Y-%m-%dT%H:%M"
                )
            else:
                self.schedule_not_before = None

            schedule_repeat_after_attr = get_element_attr(
                root, "schedule", "repeat_after")

            if schedule_repeat_after_attr is not None:
                self.schedule_repeat_after = int(schedule_repeat_after_attr)
            else:
                self.schedule_repeat_after = None

            self.schedule_slip_mode = SlipMode.from_string(get_element_attr(
                root, "schedule", "slip_mode", "drop_missed_aligned"))

            self.config_file = config_file

        except:
            # TODO
            raise

    def reload(self):
        if self.config_file is not None:
            raise RuntimeError("Can't reload, config_file is not set.")

        self.load(self.config_file)

    def save_as(self, config_file):
        root = ElementTree.Element("task")

        # TODO: Check self.id_ sanity?

        if self.title is not None:
            title_element = ElementTree.Element("title")
            title_element.text = self.title
            root.append(title_element)

        input_element = ElementTree.Element("input")
        input_element.set("href", self.input_file)
        if self.input_datastream_id is not None:
            input_element.set("datastream_id", self.input_datastream_id)
        if self.input_xccdf_id is not None:
            input_element.set("xccdf_id", self.input_xccdf_id)
        root.append(input_element)

        if self.tailoring_file is not None:
            tailoring_element = ElementTree.Element("tailoring")
            tailoring_element.set("href", self.tailoring_file)
            root.append(tailoring_element)

        if self.profile_id is not None:
            profile_element = ElementTree.Element("profile")
            profile_element.text = self.profile_id
            root.append(profile_element)

        online_remediation_element = ElementTree.Element("online_remediation")
        online_remediation_element.text = \
            "true" if self.online_remediation else "false"
        root.append(online_remediation_element)

        target_element = ElementTree.Element("target")
        target_element.text = self.target
        root.append(target_element)

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

        tree = ElementTree.ElementTree(root)
        tree.write(config_file, "utf-8")

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

    def get_task_results_dir(self, results_dir):
        return os.path.join(results_dir, self.id_)

    def list_result_ids(self, results_dir):
        """IDs are returned in reverse order sorted by strings as if they were
        integers.

        for example: ['10', '9', '8', '1']
        """

        # The lambda is there to make sure we don't consider 2 "larger"
        # than 10. For example to avoid sorted lists such as:
        # ['9', '8', '10', '1'] where we wanted ['10', '9', '8', '1']

        return sorted(
            os.listdir(self.get_task_results_dir(results_dir)), reverse=True,
            key=lambda s: (len(s), s)
        )

    def get_next_target_dir(self, results_dir):
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

        ret = os.path.join(self.get_task_results_dir(results_dir), str(last + 1))
        assert(not os.path.exists(ret))
        return ret

    def tick(self, reference_datetime, results_dir, work_in_progress_results_dir):
        """Figures out if the task should be run right now, alters the schedule
        values accordingly.

        reference datetime is passed mainly because of easier diagnostics.
        It prevents some tasks being run and others not even though they have
        the same not_before value.

        Assumption: tick is never in parallel on the same Task. It can be run
        in parallel on different tasks but at most once for 1 Task instance.
        """

        if not self.is_valid():
            raise RuntimeError("Can't tick an invalid Task.")

        if self.schedule_not_before is None:
            # this Task is not scheduled to run right now, it is disabled
            return

        if self.schedule_not_before <= reference_datetime:
            wip_result = oscap_helpers.evaluate_task(
                self, work_in_progress_results_dir)
            target_dir = self.get_next_target_dir(results_dir)

            shutil.move(wip_result, target_dir)

            self.schedule_not_before = \
                self.next_schedule_not_before(reference_datetime)

            if self.config_file:
                self.save()
