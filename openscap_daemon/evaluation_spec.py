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

from xml.etree import cElementTree as ElementTree
import os.path
import tempfile
import shutil


class SCAPInput(object):
    """Encapsulates all sorts of SCAP input, either embedded in the spec
    itself or separate in a file installed via RPM or other means.

    This does not include tailoring! That is handled separately,
    see SCAPTailoring class.
    """

    def __init__(self):
        self.file_path = None
        self.temp_file = None
        self.datastream_id = None
        self.xccdf_id = None

    def is_valid(self):
        return self.file_path is not None

    def get_xml_source(self):
        if self.file_path is None:
            return None

        with open(self.file_path, "r") as f:
            return f.read().decode("utf-8")

    def is_equivalent_to(self, other):
        return \
            self.get_xml_source() == other.get_xml_source() and \
            self.datastream_id == other.datastream_id and \
            self.xccdf_id == other.xccdf_id

    def set_file_path(self, file_path):
        """Sets given file_path to be the input file. If you use this method
        no temporary files will be allocated, the file_path will be passed to
        `oscap` as is, in its absolute form.
        """

        self.temp_file = None
        if file_path is not None:
            self.file_path = \
                os.path.abspath(file_path) if file_path is not None else None

        else:
            self.file_path = None

    def set_contents(self, input_contents):
        """Sets given input_contents XML to be the input source. This method
        allocates a temporary file that exists for the lifetime of this
        instance.
        """

        if input_contents is not None:
            self.temp_file = tempfile.NamedTemporaryFile()
            self.temp_file.write(input_contents.encode("utf-8"))
            self.temp_file.flush()

            self.file_path = os.path.abspath(self.temp_file.name)

        else:
            self.file_path = None

    def load_from_xml_element(self, element):
        input_file = element.get("href")
        if input_file is not None:
            self.set_file_path(input_file)

        else:
            input_file_contents = element.text
            self.set_contents(input_file_contents)

        self.datastream_id = element.get("datastream_id")
        self.xccdf_id = element.get("xccdf_id")

    def to_xml_element(self):
        if self.file_path is None:
            return None

        ret = ElementTree.Element("input")
        if self.temp_file is None:
            ret.set("href", self.file_path)
        else:
            with open(self.temp_file.name, "r") as f:
                ret.text = f.read().decode("utf-8")

        if self.datastream_id is not None:
            ret.set("datastream_id", self.datastream_id)
        if self.xccdf_id is not None:
            ret.set("xccdf_id", self.xccdf_id)

        return ret


class SCAPTailoring(object):
    """Encapsulates SCAP tailoring. At this point we only support separate files
    as tailorings, not the input SCAP file. The tailoring has to be plain
    XCCDF tailoring, no datastreams!
    """

    def __init__(self):
        self.file_path = None
        self.temp_file = None

    def get_xml_source(self):
        if self.file_path is None:
            return None

        with open(self.file_path, "r") as f:
            return f.read().decode("utf-8")

    def is_equivalent_to(self, other):
        return \
            self.get_xml_source() == other.get_xml_source()

    def set_file_path(self, file_path):
        """Sets given file_path to be the input file. If you use this method
        no temporary files will be allocated, the file_path will be passed to
        `oscap` as is, in its absolute form.
        """

        self.temp_file = None
        if file_path is not None:
            self.file_path = \
                os.path.abspath(file_path) if file_path is not None else None

        else:
            self.file_path = None

    def set_contents(self, input_contents):
        """Sets given input_contents XML to be the input source. This method
        allocates a temporary file that exists for the lifetime of this
        instance.
        """

        if input_contents is not None:
            self.temp_file = tempfile.NamedTemporaryFile()
            self.temp_file.write(input_contents.encode("utf-8"))
            self.temp_file.flush()

            self.file_path = os.path.abspath(self.temp_file.name)

        else:
            self.file_path = None

    def load_from_xml_element(self, element):
        input_file = element.get("href")
        if input_file is not None:
            self.set_file_path(input_file)

        else:
            input_file_contents = element.text
            self.set_contents(input_file_contents)

    def to_xml_element(self):
        if self.file_path is None:
            return None

        ret = ElementTree.Element("tailoring")
        if self.temp_file is None:
            ret.set("href", self.file_path)
        else:
            with open(self.temp_file.name, "r") as f:
                ret.text = f.read().decode("utf-8")

        return ret


class EvaluationSpec(object):
    """This class defined input content, tailoring, profile, ...
    for an SCAP evaluation task. Everything expect schedule.

    Example of a task:
        Run USGCB evaluation on RHEL6 localhost machine
    """

    def __init__(self):
        self.target = "localhost"
        self.input_ = SCAPInput()
        self.tailoring = SCAPTailoring()
        self.profile_id = None
        self.online_remediation = False

    def __str__(self):
        ret = "Evaluation spec\n"
        ret += "- target: \t%s\n" % (self.target)
        ret += "- input:\n"
        ret += "  - file: \t%s\n" % (self.input_.file_path)
        if self.input_.temp_file is not None:
            ret += "    - bundled"
        ret += "  - datastream_id: \t%s\n" % (self.input_.datastream_id)
        ret += "  - xccdf_id: \t%s\n" % (self.input_.xccdf_id)
        ret += "- tailoring file: \t%s\n" % (self.tailoring.file_file)
        if self.tailoring.temp_file is not None:
            ret += "  - bundled"
        ret += "- profile ID: \t%s\n" % (self.profile_id)
        ret += "- online remediation: \t%s\n" % \
            ("enabled" if self.online_remediation else "disabled")

        return ret

    def is_valid(self):
        if not self.input_.is_valid():
            return False

        if self.target is None:
            return False

        return True

    def is_equivalent_to(self, other):
        """Checks that both "Task self" and "Task other" are the same except for
        id_ and config_file.
        """

        return \
            self.target == other.target and \
            self.input_.is_equivalent_to(other.input_) and \
            self.tailoring.is_equivalent_to(other.tailoring) and \
            self.profile_id == other.profile_id and \
            self.online_remediation == other.online_remediation

    def load_from_xml_element(self, element):
        self.target = et_helpers.get_element_text(element, "target")

        self.input_ = SCAPInput()
        self.input_.load_from_xml_element(
            et_helpers.get_element(element, "input")
        )

        self.tailoring = SCAPTailoring()
        try:
            self.tailoring.load_from_xml_element(
                et_helpers.get_element(element, "tailoring")
            )
        except RuntimeError:
            # tailoring is optional, if it's not present just skip tailoring
            pass

        self.profile_id = et_helpers.get_element_text(element, "profile")
        self.online_remediation = \
            et_helpers.get_element_text(element, "online_remediation") == "true"

    def load_from_xml_source(self, xml_source):
        element = ElementTree.fromstring(xml_source)
        self.load_from_xml_element(element)

    def to_xml_element(self):
        ret = ElementTree.Element("evaluation_spec")

        target_element = ElementTree.Element("target")
        target_element.text = self.target
        ret.append(target_element)

        input_element = self.input_.to_xml_element()
        if input_element is not None:
            ret.append(input_element)

        tailoring_element = self.tailoring.to_xml_element()
        if tailoring_element is not None:
            ret.append(tailoring_element)

        if self.profile_id is not None:
            profile_element = ElementTree.Element("profile")
            profile_element.text = self.profile_id
            ret.append(profile_element)

        online_remediation_element = ElementTree.Element("online_remediation")
        online_remediation_element.text = \
            "true" if self.online_remediation else "false"
        ret.append(online_remediation_element)

        return ret

    def to_xml_source(self):
        element = self.to_xml_element()
        return ElementTree.tostring(element, "utf-8")

    def generate_guide(self, config):
        return oscap_helpers.generate_guide(self, config)

    def evaluate_into_dir(self, config):
        return oscap_helpers.evaluate(self, config)

    def evaluate(self, config):
        wip_result = self.evaluate_into_dir(config)
        try:
            arf = ""
            with open(os.path.join(wip_result, "arf.xml"), "r") as f:
                arf = f.read()

            stdout = ""
            with open(os.path.join(wip_result, "stdout"), "r") as f:
                stdout = f.read()

            stderr = ""
            with open(os.path.join(wip_result, "stderr"), "r") as f:
                stderr = f.read()

            exit_code = -1
            with open(os.path.join(wip_result, "exit_code"), "r") as f:
                exit_code = int(f.read())

            return (arf, stdout, stderr, exit_code)

        finally:
            shutil.rmtree(wip_result)

