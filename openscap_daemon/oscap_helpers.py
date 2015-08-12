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

# TODO: configurable
OSCAP_PATH = "oscap"
OSCAP_SSH_PATH = "oscap-ssh"


def get_profile_choices_for_input(input_file, tailoring_file):
    # Ideally oscap would have a command line to do this, but as of now it
    # doesn't so we have to implement it ourselves. Importing openscap Python
    # bindings is nasty and overkill for this.

    logging.debug(
        "Looking for profile choices in '%s' with tailoring file '%s'." %
        (input_file, tailoring_file)
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
        "Found %i profile choices in '%s' with tailoring file '%s'." %
        (len(ret), input_file, tailoring_file)
    )

    return ret


def get_generate_guide_args(spec):
    ret = [OSCAP_PATH, "xccdf", "generate", "guide"]

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


def generate_guide(spec):
    if not spec.is_valid():
        raise RuntimeError(
            "Can't generate guide for an invalid EvaluationSpec."
        )

    args = get_generate_guide_args(spec)

    logging.debug(
        "Generating guide for evaluation spec with command '%s'." %
        (" ".join(args))
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


def get_evaluation_args(spec):
    ret = []

    if spec.target == "localhost":
        ret.extend([OSCAP_PATH])

    elif spec.target.startswith("ssh://"):
        host, port = split_ssh_target(spec.target)
        ret.extend([OSCAP_SSH_PATH, host, str(port)])

    else:
        raise RuntimeError(
            "Unrecognized target '%s' in evaluation spec." % (spec.target)
        )

    ret.extend(["xccdf", "eval"])

    if spec.input_.datastream_id is not None:
        ret.extend(["--datastream-id", spec.input_.datastream_id])

    if spec.input_.xccdf_id is not None:
        ret.extend(["--xccdf-id", spec.input_.xccdf_id])

    if spec.tailoring.file_path is not None:
        ret.extend(["--tailoring-file", spec.tailoring.file_path])

    if spec.profile_id is not None:
        ret.extend(["--profile", spec.profile_id])

    if spec.online_remediation:
        ret.append("--remediate")

    # We are on purpose only interested in ARF, everything else can be
    # generated from that.
    ret.extend(["--results-arf", "arf.xml"])

    ret.append(spec.input_.file_path)

    return ret


def evaluate(spec, results_dir):
    """Calls oscap to evaluate given task, creates a uniquely named directory
    in given results_dir for it. Returns absolute path to that directory in
    case of success.

    Throws exception in case of failure.
    """

    if not spec.is_valid():
        raise RuntimeError("Can't evaluate an invalid EvaluationSpec.")

    working_directory = tempfile.mkdtemp(
        prefix="", suffix="",
        dir=results_dir
    )

    stdout_file = open(os.path.join(working_directory, "stdout"), "w")
    stderr_file = open(os.path.join(working_directory, "stderr"), "w")

    args = get_evaluation_args(spec)

    logging.debug(
        "Starting evaluation with command '%s'." %
        (" ".join(args))
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
            "Evaluated EvaluationSpec, exit code %i means the target evaluated "
            "as compliant." % (exit_code)
        )
        # TODO: Assert that arf was generated

    elif exit_code == 2:
        logging.warning(
            "Evaluated EvaluationSpec, exit code %i means the target evaluated "
            "as non-compliant!" % (exit_code)
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
            "Evaluated EvaluationSpec, unknown exit code %i!." %
            (exit_code)
        )

    return working_directory


def get_generate_report_args_for_arf(spec, arf_path):
    return [OSCAP_PATH, "xccdf", "generate", "report", arf_path]


def generate_report_for_result(spec, results_dir, result_id):
    """This function assumes that the ARF was generated using evaluate
    in this same package. That's why we can avoid --datastream-id, ...

    The behavior is undefined for generic ARFs!
    """

    if not spec.is_valid():
        raise RuntimeError("Can't generate report for any result of an "
                           "invalid EvaluationSpec.")

    arf_path = os.path.join(results_dir, str(result_id), "arf.xml")

    if not os.path.exists(arf_path):
        raise RuntimeError("Can't generate report for result '%s'. "
                           "Expected ARF at '%s' but the file doesn't exist."
                           % (result_id, arf_path))

    args = get_generate_report_args_for_arf(spec, arf_path)

    logging.debug(
        "Generating report for result %i of EvaluationSpec with command '%s'." %
        (result_id, " ".join(args))
    )

    ret = subprocess_check_output(
        args,
        shell=False
    ).decode("utf-8")

    logging.info(
        "Generated report for result %i of EvaluationSpec." %
        (result_id)
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
    "generate_guide",
    "evaluate",
    "generate_report_for_arf",
    "get_status_from_exit_code"
]
