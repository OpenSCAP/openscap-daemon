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


def generate_guide_args_for_task(task):
    ret = [OSCAP_PATH, "xccdf", "generate", "guide"]

    # TODO: Is this supported in OpenSCAP?
    if task.input_.datastream_id is not None:
        ret.extend(["--datastream-id", task.input_.datastream_id])

    # TODO: Is this supported in OpenSCAP?
    if task.input_.xccdf_id is not None:
        ret.extend(["--xccdf-id", task.input_.xccdf_id])

    # TODO: Is this supported in OpenSCAP?
    if task.tailoring.file_path is not None:
        ret.extend(["--tailoring-file", task.tailoring.file_path])

    if task.profile_id is not None:
        ret.extend(["--profile", task.profile_id])

    ret.append(task.input_.file_path)

    return ret


def generate_guide_for_task(task):
    if not task.is_valid():
        raise RuntimeError("Can't generate guide for an invalid Task.")

    args = generate_guide_args_for_task(task)

    logging.debug(
        "Generating guide for task %i with command '%s'." %
        (task.id_, " ".join(args))
    )

    ret = subprocess_check_output(
        args,
        shell=False
    ).decode("utf-8")

    logging.info(
        "Generated guide for task %i." %
        (task.id_)
    )

    return ret


def split_ssh_target(target):
    assert(target.startswith("ssh://"))

    without_prefix = target[6:]

    if ":" in without_prefix:
        host, port_str = without_prefix.split(":")
        return host, int(port_str)

    else:
        return without_prefix, 22


def evaluation_args_for_task(task):
    ret = []

    if task.target == "localhost":
        ret.extend([OSCAP_PATH])

    elif task.target.startswith("ssh://"):
        host, port = split_ssh_target(task.target)
        ret.extend([OSCAP_SSH_PATH, host, str(port)])

    else:
        raise RuntimeError(
            "Unrecognized target '%s' in task '%i'." % (task.target, task.id_)
        )

    ret.extend(["xccdf", "eval"])

    if task.input_.datastream_id is not None:
        ret.extend(["--datastream-id", task.input_.datastream_id])

    if task.input_.xccdf_id is not None:
        ret.extend(["--xccdf-id", task.input_.xccdf_id])

    if task.tailoring.file_path is not None:
        ret.extend(["--tailoring-file", task.tailoring.file_path])

    if task.profile_id is not None:
        ret.extend(["--profile", task.profile_id])

    if task.online_remediation:
        ret.append("--remediate")

    # We are on purpose only interested in ARF, everything else can be
    # generated from that.
    ret.extend(["--results-arf", "arf.xml"])

    ret.append(task.input_.file_path)

    return ret


def evaluate_task(task, task_results_dir):
    """Calls oscap to evaluate given task, creates a uniquely named directory
    in given results_dir for it. Returns absolute path to that directory in
    case of success.

    Throws exception in case of failure.
    """

    if not task.is_valid():
        raise RuntimeError("Can't evaluate an invalid Task.")

    working_directory = None
    stdout_file = None
    stderr_file = None

    working_directory = tempfile.mkdtemp(
        prefix="", suffix="",
        dir=task_results_dir
    )

    stdout_file = open(os.path.join(working_directory, "stdout"), "w")
    stderr_file = open(os.path.join(working_directory, "stderr"), "w")

    args = evaluation_args_for_task(task)

    logging.debug(
        "Starting evaluation of task '%s' with command '%s'." %
        (task.id_, " ".join(args))
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
            "Failed to execute 'oscap' while evaluating task '%s'." %
            (task.id_)
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
            "Evaluated task '%i', exit code %i means the target evaluated "
            "as compliant." % (task.id_, exit_code)
        )
        # TODO: Assert that arf was generated

    elif exit_code == 2:
        logging.warning(
            "Evaluated task '%i', exit code %i means the target evaluated "
            "as non-compliant!" % (task.id_, exit_code)
        )
        # TODO: Assert that arf was generated

    elif exit_code == 1:
        logging.error(
            "Task '%i' failed to evaluate, oscap returned 1 as exit code, "
            "it won't be possible to get ARF or generate reports for this "
            "result!" % (task.id_)
        )
        # TODO: Assert that arf was NOT generated

    else:
        logging.error(
            "Evaluated task '%i', unknown exit code %i!." %
            (task.id_, exit_code)
        )

    return working_directory


def generate_report_args_for_result(task, arf_path):
    return [OSCAP_PATH, "xccdf", "generate", "report", arf_path]


def generate_report_for_result(task, results_dir, result_id):
    """This function assumes that the ARF was generated using evaluate_task
    in this same package. That's why we can avoid --datastream-id, ...

    The behavior is undefined for generic ARFs!
    """

    if not task.is_valid():
        raise RuntimeError("Can't generate report for any result of an "
                           "invalid Task.")

    arf_path = os.path.join(results_dir, str(result_id), "arf.xml")

    if not os.path.exists(arf_path):
        raise RuntimeError("Can't generate report for result '%s'. "
                           "Expected ARF at '%s' but the file doesn't exist."
                           % (result_id, arf_path))

    args = generate_report_args_for_result(task, arf_path)

    logging.debug(
        "Generating report for result %i of task %i with command '%s'." %
        (result_id, task.id_, " ".join(args))
    )

    ret = subprocess_check_output(
        args,
        shell=False
    ).decode("utf-8")

    logging.info(
        "Generated report for result %i of task %i." %
        (result_id, task.id_)
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
    "generate_guide_for_task",
    "evaluate_task",
    "generate_report_for_result",
    "get_status_from_exit_code"
]
