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


import subprocess
import tempfile
import os.path
import logging

from xml.etree import cElementTree as ElementTree
from openscap_daemon import et_helpers
from openscap_daemon.compat import subprocess_check_output


class EvaluationMode(object):
    UNKNOWN = -1

    SOURCE_DATASTREAM = 1
    OVAL = 2
    CVE_SCAN = 3

    @staticmethod
    def to_string(value):
        if value == EvaluationMode.SOURCE_DATASTREAM:
            return "sds"
        elif value == EvaluationMode.OVAL:
            return "oval"
        elif value == EvaluationMode.CVE_SCAN:
            return "cve_scan"

        else:
            return "unknown"

    @staticmethod
    def from_string(value):
        if value == "sds":
            return EvaluationMode.SOURCE_DATASTREAM
        elif value == "oval":
            return EvaluationMode.OVAL
        elif value == "cve_scan":
            return EvaluationMode.CVE_SCAN

        else:
            return EvaluationMode.UNKNOWN


def get_profile_choices_for_input(input_file, tailoring_file):
    # Ideally oscap would have a command line to do this, but as of now it
    # doesn't so we have to implement it ourselves. Importing openscap Python
    # bindings is nasty and overkill for this.

    logging.debug(
        "Looking for profile choices in '%s' with tailoring file '%s'.",
        input_file, tailoring_file
    )

    ret = {}

    def scrape_profiles(tree, namespace, dest):
        for elem in tree.iter("{%s}Profile" % (namespace)):
            id_ = elem.get("id")
            if id_ is None:
                continue

            title = et_helpers.get_element_text(
                elem, "{%s}title" % (namespace), ""
            )

            dest[id_] = title

    input_tree = ElementTree.parse(input_file)

    scrape_profiles(
        input_tree, "http://checklists.nist.gov/xccdf/1.1", ret
    )
    scrape_profiles(
        input_tree, "http://checklists.nist.gov/xccdf/1.2", ret
    )

    if tailoring_file:
        tailoring_tree = ElementTree.parse(tailoring_file)

        scrape_profiles(
            tailoring_tree, "http://checklists.nist.gov/xccdf/1.1", ret
        )
        scrape_profiles(
            tailoring_tree, "http://checklists.nist.gov/xccdf/1.2", ret
        )

    logging.info(
        "Found %i profile choices in '%s' with tailoring file '%s'.",
        len(ret), input_file, tailoring_file
    )

    return ret


def get_generate_guide_args(spec, config):
    assert(spec.mode == EvaluationMode.SOURCE_DATASTREAM)

    ret = [config.oscap_path, "xccdf", "generate", "guide"]

    # TODO: Is this supported in OpenSCAP?
    if spec.input_.datastream_id is not None:
        ret.extend(["--datastream-id", spec.input_.datastream_id])

    # TODO: Is this supported in OpenSCAP?
    if spec.input_.xccdf_id is not None:
        ret.extend(["--xccdf-id", spec.input_.xccdf_id])

    # TODO: Is this supported in OpenSCAP?
    if spec.tailoring.file_path is not None:
        ret.extend(["--tailoring-file", spec.tailoring.file_path])

    if spec.profile_id is not None:
        ret.extend(["--profile", spec.profile_id])

    ret.append(spec.input_.file_path)

    return ret


def generate_guide(spec, config):
    if spec.mode != EvaluationMode.SOURCE_DATASTREAM:
        raise RuntimeError(
            "Can't generate guide for an EvaluationSpec with mode '%s'. "
            "Generating an HTML guide only works for 'sds' mode."
            % (EvaluationMode.to_string(spec.mode))
        )

    if not spec.is_valid():
        raise RuntimeError(
            "Can't generate guide for an invalid EvaluationSpec."
        )

    args = get_generate_guide_args(spec, config)

    logging.debug(
        "Generating guide for evaluation spec with command '%s'.",
        " ".join(args)
    )

    ret = subprocess_check_output(
        args,
        shell=False
    ).decode("utf-8")

    logging.info("Generated guide for evaluation spec.")

    return ret


def split_ssh_target(target):
    assert(target.startswith("ssh://"))

    without_prefix = target[6:]

    if ":" in without_prefix:
        host, port_str = without_prefix.split(":")
        return host, int(port_str)

    else:
        return without_prefix, 22


def get_evaluation_args(spec, config):
    ret = []

    if spec.target == "localhost":
        if config.oscap_path == "":
            raise RuntimeError(
                "Target '%s' requires the oscap tool which hasn't been found" %
                (spec.target)
            )
        ret.extend([config.oscap_path])

    elif spec.target.startswith("ssh://"):
        if config.oscap_ssh_path == "":
            raise RuntimeError(
                "Target '%s' requires the oscap-ssh tool which hasn't been "
                "found" % (spec.target)
            )
        host, port = split_ssh_target(spec.target)
        ret.extend([config.oscap_ssh_path, host, str(port)])

    elif spec.target.startswith("docker-image://"):
        if config.oscap_ssh_path == "":
            raise RuntimeError(
                "Target '%s' requires the oscap-docker tool which hasn't been "
                "found" % (spec.target)
            )
        image_name = spec.target[len("docker-image://"):]
        ret.extend([config.oscap_docker_path, "image", image_name])

    elif spec.target.startswith("docker-container://"):
        if config.oscap_ssh_path == "":
            raise RuntimeError(
                "Target '%s' requires the oscap-docker tool which hasn't been "
                "found" % (spec.target)
            )
        container_name = spec.target[len("docker-container://"):]
        ret.extend([config.oscap_docker_path, "container", container_name])

    elif spec.target.startswith("vm-domain://"):
        if config.oscap_vm_path == "":
            raise RuntimeError(
                "Target '%s' requires the oscap-vm tool which hasn't been "
                "found" % (spec.target)
            )
        domain_name = spec.target[len("vm-domain://"):]
        ret.extend([config.oscap_vm_path, "domain", domain_name])

    elif spec.target.startswith("vm-image://"):
        if config.oscap_vm_path == "":
            raise RuntimeError(
                "Target '%s' requires the oscap-vm tool which hasn't been "
                "found" % (spec.target)
            )
        storage_name = spec.target[len("vm-image://"):]
        ret.extend([config.oscap_vm_path, "image", storage_name])

    elif spec.target.startswith("chroot://"):
        if config.oscap_chroot_path == "":
            raise RuntimeError(
                "Target '%s' requires the oscap-chroot tool which hasn't been "
                "found" % (spec.target)
            )
        path = spec.target[len("chroot://"):]
        ret.extend([config.oscap_chroot_path, path])

    else:
        raise RuntimeError(
            "Unrecognized target '%s' in evaluation spec." % (spec.target)
        )

    ret.extend(spec.get_oscap_arguments(config))
    return ret


def evaluate(spec, config):
    """Calls oscap to evaluate given task, creates a uniquely named directory
    in given results_dir for it. Returns absolute path to that directory in
    case of success.

    Throws exception in case of failure.
    """

    if not spec.is_valid():
        raise RuntimeError("Can't evaluate an invalid EvaluationSpec.")

    working_directory = tempfile.mkdtemp(
        prefix="", suffix="",
        dir=config.work_in_progress_dir
    )

    stdout_file = open(os.path.join(working_directory, "stdout"), "w")
    stderr_file = open(os.path.join(working_directory, "stderr"), "w")

    args = get_evaluation_args(spec, config)

    logging.debug(
        "Starting evaluation with command '%s'.",
        " ".join(args)
    )

    exit_code = 1

    try:
        exit_code = subprocess.call(
            args,
            cwd=working_directory,
            stdout=stdout_file,
            stderr=stderr_file,
            shell=False
        )

    except:
        logging.exception(
            "Failed to execute 'oscap' while evaluating EvaluationSpec."
        )

    stdout_file.flush()
    stderr_file.flush()

    with open(os.path.join(working_directory, "exit_code"), "w") as f:
        f.write("%i" % (exit_code))

    # Exit code 0 means evaluation was successful and machine is compliant.
    # Exit code 1 means there was an error while evaluating.
    # Exit code 2 means there were no errors but the machine is not compliant.

    if exit_code == 0:
        logging.info(
            "Evaluated EvaluationSpec, exit code 0 means the target evaluated "
            "as compliant."
        )
        # TODO: Assert that arf was generated

    elif exit_code == 2:
        logging.warning(
            "Evaluated EvaluationSpec, exit code 2 means the target evaluated "
            "as non-compliant!"
        )
        # TODO: Assert that arf was generated

    elif exit_code == 1:
        logging.error(
            "EvaluationSpec failed to evaluate, oscap returned 1 as exit code, "
            "it may not be possible to get ARF or generate reports for this "
            "result!"
        )
        # TODO: Assert that arf was NOT generated

    else:
        logging.error(
            "Evaluated EvaluationSpec, unknown exit code %i!.", exit_code
        )

    return working_directory


def get_generate_report_args_for_results(spec, results_path, config):
    if spec.mode == EvaluationMode.SOURCE_DATASTREAM:
        # results_path is an ARF XML file
        return [config.oscap_path, "xccdf", "generate", "report", results_path]

    elif spec.mode == EvaluationMode.OVAL:
        # results_path is an OVAL results XML file
        return [config.oscap_path, "oval", "generate", "report", results_path]

    elif spec.mode == EvaluationMode.CVE_SCAN:
        # results_path is an OVAL results XML file
        return [config.oscap_path, "oval", "generate", "report", results_path]

    else:
        raise RuntimeError("Unknown evaluation mode")


def generate_report_for_result(spec, results_dir, result_id, config):
    """This function assumes that the ARF was generated using evaluate
    in this same package. That's why we can avoid --datastream-id, ...

    The behavior is undefined for generic ARFs!
    """

    if not spec.is_valid():
        raise RuntimeError("Can't generate report for any result of an "
                           "invalid EvaluationSpec.")

    results_path = os.path.join(results_dir, str(result_id), "results.xml")

    if not os.path.exists(results_path):
        raise RuntimeError("Can't generate report for result '%s'. Expected "
                           "results XML at '%s' but the file doesn't exist."
                           % (result_id, results_path))

    args = get_generate_report_args_for_results(spec, results_path, config)

    logging.debug(
        "Generating report for result %i of EvaluationSpec with command '%s'.",
        result_id, " ".join(args)
    )

    ret = subprocess_check_output(
        args,
        shell=False
    ).decode("utf-8")

    logging.info(
        "Generated report for result %i of EvaluationSpec.", result_id
    )

    return ret


def get_status_from_exit_code(exit_code):
    """Returns human readable status based on given `oscap` exit_code
    """

    status = "Unknown (exit_code = %i)" % (exit_code)
    if exit_code == 0:
        status = "Compliant"
    elif exit_code == 1:
        status = "Non-Compliant"
    elif exit_code == 2:
        status = "Evaluation Error"

    return status


__all__ = [
    "get_profile_choices_for_input",
    "generate_guide",
    "evaluate",
    "generate_report_for_result",
    "get_status_from_exit_code"
]
