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

    return subprocess.check_output(
        generate_guide_args_for_task(task),
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


def evaluate_task(task, results_dir):
    if not task.is_valid():
        raise RuntimeError("Can't evaluate an invalid Task.")

    working_directory = None
    stdout_file = None
    stderr_file = None

    try:
        working_directory = tempfile.mkdtemp(
            prefix="", suffix="",
            dir=os.path.join(results_dir, task.id_)
        )

        stdout_file = open(os.path.join(working_directory, "stdout"), "w")
        stderr_file = open(os.path.join(working_directory, "stderr"), "w")

        exit_code = subprocess.call(
            evaluation_args_for_task(task),
            cwd=working_directory,
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

        if working_directory is not None:
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
    #    if working_directory is not None:
    #        shutil.rmtree(working_directory)


def generate_report_args_for_result(task, arf_path):
    # TODO
    assert(task.target == "localhost")

    ret = [OSCAP_PATH, "xccdf", "generate", "report"]

    ret.append(arf_path)

    return ret


def generate_report_for_result(task, results_dir, result_id):
    if not task.is_valid():
        raise RuntimeError("Can't generate report for any result of an "
                           "invalid Task.")

    arf_path = os.path.join(results_dir, task.id_, result_id, "results-arf.xml")

    if not os.path.exists(arf_path):
        raise RuntimeError("Can't generate report for result '%s'. "
                           "Expected ARF at '%s' but the file doesn't exist.")

    return subprocess.check_output(
        generate_report_args_for_result(task, arf_path),
        shell=False
    )


__all__ = [
    "generate_guide_for_task",
    "EvaluationFailedError", "evaluate_task",
    "generate_report_for_result"
]
