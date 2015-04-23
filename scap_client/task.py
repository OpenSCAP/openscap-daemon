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


from xml.etree import cElementTree as ElementTree
from datetime import datetime, timedelta
from scap_client.et_helpers import get_element_attr, get_element_text
import subprocess
import tempfile
import os.path
# import shutil

# TODO: configurable
OSCAP_PATH = "oscap"


class SlipMode(object):
    UNKNOWN = 0
    NO_SLIP = 1

    @staticmethod
    def from_string(slip_mode):
        if slip_mode == "no_slip":
            return SlipMode.NO_SLIP

        return SlipMode.UNKNOWN

    @staticmethod
    def to_string(slip_mode):
        if slip_mode == SlipMode.NO_SLIP:
            return "no_slip"

        return "unknown"


class EvaluationFailedError(RuntimeError):
    def __init__(self, msg):
        super(self, RuntimeError).__init__(msg)


class Task(object):
    """
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
        self.target = None
        self.schedule_not_before = None
        self.schedule_repeat_after = None
        self.schedule_slip_mode = SlipMode.NO_SLIP

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
                root, "schedule", "slip_mode"))

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

    def generate_evaluation_args(self):
        # TODO
        assert(self.target == "localhost")

        ret = [OSCAP_PATH, "xccdf", "eval"]

        if self.input_datastream_id is not None:
            ret.extend(["--datastream-id", self.input_datastream_id])

        if self.input_xccdf_id is not None:
            ret.extend(["--xccdf-id", self.input_xccdf_id])

        if self.profile_id is not None:
            ret.extend(["--profile", self.profile_id])

        if self.tailoring_file is not None:
            ret.extend(["--tailoring-file", self.tailoring_file])

        # We are on purpose only interested in ARF, everything else can be
        # generated from that.
        ret.extend(["--results-arf", "results-arf.xml"])

        ret.append(self.input_file)

        return ret

    def evaluate(self, results_dir):
        if not self.is_valid():
            raise RuntimeError("Can't evaluate an invalid Task.")

        cwd = None
        stdout_file = None
        stderr_file = None
        try:
            cwd = tempfile.mkdtemp(
                prefix="", suffix="",
                dir=os.path.join(results_dir, self.id_)
            )

            stdout_file = open(os.path.join(cwd, "stdout"), "w")
            stderr_file = open(os.path.join(cwd, "stderr"), "w")

            exit_code = subprocess.call(
                self.generate_evaluation_args(),
                cwd=cwd,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False
            )

            # We only care about exit_code not being 1, if evaluation says
            # the machine is not compliant we will see it in the ARF later.

            if exit_code == 1:
                # TODO: Improve the exception message
                raise EvaluationFailedError(
                    "`oscap` evaluation failed with exit code %i" % (exit_code)
                )

        except EvaluationFailedError as e:
            stdout_contents = ""
            stderr_contents = ""

            if cwd is not None:
                # Can't use just open(file).read(), that doesn't guarantee
                # that Python will close the file immediately

                if stdout_file is not None:
                    with open(stdout_file, "r") as f:
                        stdout_contents = f.read()
                if stderr_file is not None:
                    with open(stderr_file, "r") as f:
                        stderr_contents = f.read()

            raise RuntimeError(
                "%s\n\n"
                "stdout:\n"
                "%s\n\n"
                "stderr:\n"
                "%s\n\n" % (e, stdout_contents, stderr_contents)
            )

        # finally:
        #    if cwd is not None:
        #        shutil.rmtree(cwd)

    def next_schedule_not_before(self):
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
        else:
            raise RuntimeError("Unrecognized schedule_slip_mode.")

    def tick(self, reference_datetime, results_dir):
        """Figures out if the task should be run right now, alters the schedule
        values accordingly.

        reference datetime is passed mainly because of easier diagnostics.
        It prevents some tasks being run and others not even though they have
        the same not_before value.
        """

        if not self.is_valid():
            raise RuntimeError("Can't tick an invalid Task.")

        if self.schedule_not_before is None:
            # this Task is not scheduled to run right now, it is disabled
            return

        if self.schedule_not_before <= reference_datetime:
            try:
                self.evaluate(results_dir)
            except:
                # TODO
                raise
                pass

            self.schedule_not_before = self.next_schedule_not_before()

            if self.config_file:
                self.save()
