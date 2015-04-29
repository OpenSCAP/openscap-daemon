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


import subprocess
import tempfile
import os.path
import shutil
import logging


# TODO: configurable
OSCAP_PATH = "oscap"


def generate_guide_args_for_task(task):
    # TODO
    assert(task.target == "localhost")

    ret = [OSCAP_PATH, "xccdf", "generate", "guide"]

    # TODO: Is this supported in OpenSCAP?
    if task.input_datastream_id is not None:
        ret.extend(["--datastream-id", task.input_datastream_id])

    # TODO: Is this supported in OpenSCAP?
    if task.input_xccdf_id is not None:
        ret.extend(["--xccdf-id", task.input_xccdf_id])

    # TODO: Is this supported in OpenSCAP?
    if task.tailoring_file is not None:
        ret.extend(["--tailoring-file", task.tailoring_file])

    if task.profile_id is not None:
        ret.extend(["--profile", task.profile_id])

    ret.append(task.input_file)

    return ret


def generate_guide_for_task(task):
    if not task.is_valid():
        raise RuntimeError("Can't generate guide for an invalid Task.")

    args = generate_guide_args_for_task(task)

    logging.debug(
        "Generating guide for task %i with command '%s'." %
        (task.id_, " ".join(args))
    )

    return subprocess.check_output(
        args,
        shell=False
    )


class EvaluationFailedError(RuntimeError):
    def __init__(self, msg):
        super(self, RuntimeError).__init__(msg)


def evaluation_args_for_task(task):
    # TODO
    assert(task.target == "localhost")

    ret = [OSCAP_PATH, "xccdf", "eval"]

    if task.input_datastream_id is not None:
        ret.extend(["--datastream-id", task.input_datastream_id])

    if task.input_xccdf_id is not None:
        ret.extend(["--xccdf-id", task.input_xccdf_id])

    if task.tailoring_file is not None:
        ret.extend(["--tailoring-file", task.tailoring_file])

    if task.profile_id is not None:
        ret.extend(["--profile", task.profile_id])

    if task.online_remediation:
        ret.append("--remediate")

    # We are on purpose only interested in ARF, everything else can be
    # generated from that.
    ret.extend(["--results-arf", "results-arf.xml"])

    ret.append(task.input_file)

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

    exit_code = subprocess.call(
        args,
        cwd=working_directory,
        stdout=stdout_file,
        stderr=stderr_file,
        shell=False
    )

    logging.debug(
        "Finished evaluation of task '%s', exit code %i." %
        (task.id_, exit_code)
    )

    # Exit code 0 means evaluation was successful and machine is compliant.
    # Exit code 1 means there was an error while evaluating.
    # Exit code 2 means there were no errors but the machine is not compliant.
    # We will treat all exit codes except 0 and 2 as fatal errors.

    if exit_code not in [0, 2]:
        stdout_contents = "Unknown"
        stderr_contents = "Unknown"

        if working_directory is not None:
            # Can't use just open(file).read(), that doesn't guarantee
            # that Python will close the file immediately

            if stdout_file is not None:
                try:
                    with open(stdout_file, "r") as f:
                        stdout_contents = f.read()
                except:
                    pass

            if stderr_file is not None:
                try:
                    with open(stderr_file, "r") as f:
                        stderr_contents = f.read()
                except:
                    pass

        if working_directory is not None:
            shutil.rmtree(working_directory)

        raise RuntimeError(
            "`oscap` exit code was %i! Expected 0 or 2.\n\n"
            "stdout:\n"
            "%s\n\n"
            "stderr:\n"
            "%s\n\n" % (exit_code, stdout_contents, stderr_contents)
        )

    return working_directory


def generate_report_args_for_result(task, arf_path):
    # TODO
    assert(task.target == "localhost")

    ret = [OSCAP_PATH, "xccdf", "generate", "report"]

    ret.append(arf_path)

    return ret


def generate_report_for_result(task, results_dir, result_id):
    """This function assumes that the ARF was generated using evaluate_task
    in this same package. That's why we can avoid --datastream-id, ...

    The behavior is undefined for generic ARFs!
    """

    if not task.is_valid():
        raise RuntimeError("Can't generate report for any result of an "
                           "invalid Task.")

    arf_path = os.path.join(results_dir, str(result_id), "results-arf.xml")

    if not os.path.exists(arf_path):
        raise RuntimeError("Can't generate report for result '%s'. "
                           "Expected ARF at '%s' but the file doesn't exist."
                           % (result_id, arf_path))

    args = generate_report_args_for_result(task, arf_path)

    logging.debug(
        "Generating report for result %i of task %i with command '%s'." %
        (result_id, task.id_, " ".join(args))
    )

    return subprocess.check_output(
        args,
        shell=False
    )


__all__ = [
    "generate_guide_for_task",
    "EvaluationFailedError", "evaluate_task",
    "generate_report_for_result"
]
