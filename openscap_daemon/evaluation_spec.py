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
import io


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

        with io.open(self.file_path, "r", encoding="utf-8") as f:
            return f.read()

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
            with io.open(self.temp_file.name, "r", encoding="utf-8") as f:
                ret.text = f.read()

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

        with io.open(self.file_path, "r", encoding="utf-8") as f:
            return f.read()

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
            with io.open(self.temp_file.name, "r", encoding="utf-8") as f:
                ret.text = f.read()

        return ret


class EvaluationSpec(object):
    """This class defined input content, tailoring, profile, ...
    for an SCAP evaluation task. Everything expect schedule.

    Example of a task:
        Run USGCB evaluation on RHEL6 localhost machine
    """

    def __init__(self):
        self.mode = oscap_helpers.EvaluationMode.SOURCE_DATASTREAM
        self.target = "localhost"
        self.input_ = SCAPInput()
        self.tailoring = SCAPTailoring()
        self.profile_id = None
        self.online_remediation = False
        self.cpe_hints = []

    def __str__(self):
        ret = "Evaluation spec\n"
        ret += "- mode: \t%s\n" % \
            (oscap_helpers.EvaluationMode.to_string(self.mode))
        ret += "- target: \t%s\n" % (self.target)
        ret += "- input:\n"
        ret += "  - file: \t%s\n" % (self.input_.file_path)
        if self.input_.temp_file is not None:
            ret += "    - bundled"
        ret += "  - datastream_id: \t%s\n" % (self.input_.datastream_id)
        ret += "  - xccdf_id: \t%s\n" % (self.input_.xccdf_id)
        ret += "- tailoring file: \t%s\n" % (self.tailoring.file_path)
        if self.tailoring.temp_file is not None:
            ret += "  - bundled"
        ret += "- profile ID: \t%s\n" % (self.profile_id)
        ret += "- online remediation: \t%s\n" % \
            ("enabled" if self.online_remediation else "disabled")
        ret += "- CPE hints: \t%s\n" % \
            ("none" if len(self.cpe_hints) == 0 else ", ".join(self.cpe_hints))

        return ret

    def is_valid(self):
        if self.mode == oscap_helpers.EvaluationMode.UNKNOWN:
            return False

        if self.target is None:
            return False

        # cve_scan and standard_scan modes don't require the input element
        if self.mode not in [oscap_helpers.EvaluationMode.CVE_SCAN,
                             oscap_helpers.EvaluationMode.STANDARD_SCAN] and \
           not self.input_.is_valid():
            return False

        return True

    def is_equivalent_to(self, other):
        """Checks that both "Task self" and "Task other" are the same except for
        id_ and config_file.
        """

        return \
            self.mode == other.mode and \
            self.target == other.target and \
            self.input_.is_equivalent_to(other.input_) and \
            self.tailoring.is_equivalent_to(other.tailoring) and \
            self.profile_id == other.profile_id and \
            self.online_remediation == other.online_remediation and \
            self.cpe_hints == other.cpe_hints

    def load_from_xml_element(self, element):
        self.mode = oscap_helpers.EvaluationMode.from_string(
            et_helpers.get_element_text(element, "mode", "sds")
        )

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

        cpe_hints_str = et_helpers.get_element_text(element, "cpe_hints")
        self.cpe_hints = []
        if cpe_hints_str is not None:
            for cpe_hint in cpe_hints_str.split(", "):
                self.cpe_hints.append(cpe_hint)

    def load_from_xml_source(self, xml_source):
        element = ElementTree.fromstring(xml_source)
        self.load_from_xml_element(element)

    def load_from_xml_file(self, file_):
        element = ElementTree.parse(file_)
        self.load_from_xml_element(element)

    def to_xml_element(self):
        ret = ElementTree.Element("evaluation_spec")

        mode_element = ElementTree.Element("mode")
        mode_element.text = oscap_helpers.EvaluationMode.to_string(self.mode)
        ret.append(mode_element)

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

        if len(self.cpe_hints) > 0:
            cpe_hints_element = ElementTree.Element("cpe_hints")
            cpe_hints_element.text = ", ".join(self.cpe_hints)
            ret.append(cpe_hints_element)

        return ret

    def to_xml_source(self):
        element = self.to_xml_element()
        return ElementTree.tostring(element, "utf-8")

    def get_cpe_ids(self, config):
        cpe_ids = self.cpe_hints
        if len(cpe_ids) == 0:
            cpe_ids = EvaluationSpec.detect_CPEs_of_target(
                self.target, config
            )

        return cpe_ids

    def select_profile_by_suffix(self, profile_suffix):
        input_file = self.input_.file_path
        if input_file is None:
            raise RuntimeError("No SCAP content file was set in the EvaluationSpec")
        profiles = oscap_helpers.get_profile_choices_for_input(input_file, None)
        profile_id_match = False
        for p in profiles:
            if p.endswith(profile_suffix):
                if profile_id_match:
                    raise RuntimeError("Found multiple profiles with suffix %s." % profile_suffix)
                else:
                    self.profile_id = p
                    profile_id_match = True
        if profile_id_match:
            return self.profile_id
        else:
            raise RuntimeError("No profile with suffix %s" % profile_suffix)

    def generate_guide(self, config):
        if self.mode == oscap_helpers.EvaluationMode.SOURCE_DATASTREAM:
            return oscap_helpers.generate_guide(self, config)

        elif self.mode == oscap_helpers.EvaluationMode.OVAL:
            # TODO: improve this
            return "<html><body>OVAL evaluation</body></html>"

        elif self.mode == oscap_helpers.EvaluationMode.CVE_SCAN:
            # TODO: improve this
            return "<html><body>CVE scan evaluation</body></html>"

        elif self.mode == oscap_helpers.EvaluationMode.STANDARD_SCAN:
            return oscap_helpers.generate_guide(self, config)

        raise RuntimeError("Unknown EvaluationMode %i" % (self.mode))

    def generate_fix(self, config, fix_type):
        if self.mode in [oscap_helpers.EvaluationMode.SOURCE_DATASTREAM,
                         oscap_helpers.EvaluationMode.STANDARD_SCAN]:
            return oscap_helpers.generate_fix(self, config, fix_type)
        raise RuntimeError("Unsupported EvaluationMode %i" % (self.mode))

    def get_oscap_guide_arguments(self, config):
        ret = []

        if self.mode == oscap_helpers.EvaluationMode.SOURCE_DATASTREAM:
            # TODO: Is this supported in OpenSCAP?
            if self.input_.datastream_id is not None:
                ret.extend(["--datastream-id", self.input_.datastream_id])

            # TODO: Is this supported in OpenSCAP?
            if self.input_.xccdf_id is not None:
                ret.extend(["--xccdf-id", self.input_.xccdf_id])

            # TODO: Is this supported in OpenSCAP?
            if self.tailoring.file_path is not None:
                ret.extend(["--tailoring-file", self.tailoring.file_path])

            if self.profile_id is not None:
                ret.extend(["--profile", self.profile_id])

            ret.append(self.input_.file_path)

        elif self.mode == oscap_helpers.EvaluationMode.STANDARD_SCAN:
            # TODO: Is this supported in OpenSCAP?
            if self.tailoring.file_path is not None:
                ret.extend(["--tailoring-file", self.tailoring.file_path])

            ret.extend(["--profile",
                        "xccdf_org.ssgproject.content_profile_standard"])

            ret.append(config.get_ssg_sds(self.get_cpe_ids(config)))

        else:
            raise NotImplementedError("This EvaluationMode is unsupported here!")

        return ret

    def get_oscap_arguments(self, config):
        if self.mode == oscap_helpers.EvaluationMode.SOURCE_DATASTREAM:
            ret = ["xccdf", "eval"]

            if self.input_.datastream_id is not None:
                ret.extend(["--datastream-id", self.input_.datastream_id])

            if self.input_.xccdf_id is not None:
                ret.extend(["--xccdf-id", self.input_.xccdf_id])

            if self.tailoring.file_path is not None:
                ret.extend(["--tailoring-file", self.tailoring.file_path])

            if self.profile_id is not None:
                ret.extend(["--profile", self.profile_id])

            if self.online_remediation:
                ret.append("--remediate")

            # We are on purpose only interested in ARF, everything else can be
            # generated from that.
            ret.extend(["--results-arf", "results.xml"])

            ret.append(self.input_.file_path)

        elif self.mode == oscap_helpers.EvaluationMode.OVAL:
            ret = ["oval", "eval"]
            ret.extend(["--results", "results.xml"])

            # Again, we are only interested in OVAL results, everything else can
            # be generated.
            ret.append(self.input_.file_path)

        elif self.mode == oscap_helpers.EvaluationMode.CVE_SCAN:
            ret = ["oval", "eval"]
            ret.extend(["--results", "results.xml"])

            # Again, we are only interested in OVAL results, everything else can
            # be generated.
            ret.append(config.get_cve_feed(self.get_cpe_ids(config)))

        elif self.mode == oscap_helpers.EvaluationMode.STANDARD_SCAN:
            ret = ["xccdf", "eval"]

            if self.tailoring.file_path is not None:
                ret.extend(["--tailoring-file", self.tailoring.file_path])

            if self.profile_id is None:
                ret.extend(["--profile",
                        "xccdf_org.ssgproject.content_profile_standard"])
            else:
                ret.extend(["--profile", self.profile_id])

            if self.online_remediation:
                ret.append("--remediate")

            # We are on purpose only interested in ARF, everything else can be
            # generated from that.
            ret.extend(["--results-arf", "results.xml"])

            ret.append(config.get_ssg_sds(self.get_cpe_ids(config)))

        else:
            raise RuntimeError("Unknown evaluation mode %i" % (self.mode))

        return ret

    def evaluate_into_dir(self, config):
        return oscap_helpers.evaluate(self, config)

    def evaluate(self, config):
        wip_result = self.evaluate_into_dir(config)
        try:
            exit_code = -1
            with io.open(os.path.join(wip_result, "exit_code"), "r",
                         encoding="utf-8") as f:
                exit_code = int(f.read())

            stdout = ""
            with io.open(os.path.join(wip_result, "stdout"), "r",
                         encoding="utf-8") as f:
                stdout = f.read()

            stderr = ""
            with io.open(os.path.join(wip_result, "stderr"), "r",
                         encoding="utf-8") as f:
                stderr = f.read()

            results = ""
            try:
                with io.open(os.path.join(wip_result, "results.xml"), "r",
                             encoding="utf-8") as f:
                    results = f.read()
            except Exception as e:
                raise RuntimeError(
                    "Failed to read results.xml of EvaluationSpec evaluation.\n"
                    "stdout:\n%s\n\nstderr:\n%s\n\nexception: %s" %
                    (stdout, stderr, e)
                )

            return (results, stdout, stderr, exit_code)

        finally:
            shutil.rmtree(wip_result)

    @staticmethod
    def detect_CPEs_of_target(target, config):
        """Returns list of CPEs that are applicable on given target. For example
        if the target is a Red Hat Enterprise Linux 7 machine this static method
        would return:
        ["cpe:/o:redhat:enterprise_linux", "cpe:/o:redhat:enterprise_linux:7"]
        """

        # We detect the CPEs by running the OpenSCAP CPE OVAL and looking at
        # positive definitions.

        if config.cpe_oval_path == "":
            raise RuntimeError(
                "Cannot detect CPEs without the OpenSCAP CPE OVAL. Please set "
                "its path in the config file"
            )

        es = EvaluationSpec()
        es.mode = oscap_helpers.EvaluationMode.OVAL
        es.target = target
        es.input_.set_file_path(config.cpe_oval_path)

        results, stdout, stderr, exit_code = es.evaluate(config)
        if exit_code != 0:
            raise RuntimeError("Failed to detect CPEs of target '%s'.\n\n"
                               "stdout:\n%s\n\nstderr:\n%s"
                               % (target, stdout, stderr))

        namespaces = {
            "ovalres": "http://oval.mitre.org/XMLSchema/oval-results-5",
            "ovaldef": "http://oval.mitre.org/XMLSchema/oval-definitions-5"
        }
        results_tree = ElementTree.fromstring(results)
        # first we collect all definition ids that resulted in true
        definition_ids = []
        for definition in results_tree.findall(
                "./ovalres:results/ovalres:system/ovalres:definitions/"
                "ovalres:definition[@result='true']", namespaces):
            def_id_attr = definition.get("definition_id")
            if def_id_attr is None:
                continue
            definition_ids.append(def_id_attr)

        cpe_ids = []
        # now we need to lookup the CPE ID for each definition id
        for definition_id in definition_ids:
            for reference in results_tree.findall(
                    "./ovaldef:oval_definitions/ovaldef:definitions/"
                    "ovaldef:definition[@id='%s']/ovaldef:metadata/"
                    "ovaldef:reference[@source='CPE']" % (definition_id),
                    namespaces):
                ref_id = reference.get("ref_id")
                if ref_id is None:
                    continue

                cpe_ids.append(ref_id)

        return cpe_ids
