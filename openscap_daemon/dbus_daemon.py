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

from openscap_daemon import System
from openscap_daemon import EvaluationSpec
from openscap_daemon import dbus_utils
from openscap_daemon.cve_scanner.cve_scanner import Worker

import dbus
import dbus.service
import threading
from datetime import datetime
# TODO: Do we want to depend on docker for *ALL* functionality?
import docker
import json


# Internal note: Python does not support unsigned long integer while dbus does,
# to avoid weird issues I just use 64bit integer in the interface signatures.
# "2^63-1 IDs should be enough for everyone."


class OpenSCAPDaemonDbus(dbus.service.Object):
    def __init__(self, bus, config_file):
        super(OpenSCAPDaemonDbus, self).__init__(bus, dbus_utils.OBJECT_PATH)

        self.system = System(config_file)
        self.system.load_tasks()

        self.system_worker_thread = threading.Thread(
            target=lambda: self.system.schedule_tasks_worker()
        )
        self.system_worker_thread.daemon = True
        self.system_worker_thread.start()

        # TODO: Move to System
        self.docker_conn = docker.Client()

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="", out_signature="as")
    def GetSSGChoices(self):
        """Retrieves absolute paths of SSG source datastreams that are
        available.
        """
        return self.system.get_ssg_choices()

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="ss", out_signature="a{ss}")
    def GetProfileChoicesForInput(self, input_file, tailoring_file):
        """Figures out profile ID -> profile title mappings of all available
        profiles given the input_file and (optionally) the tailoring_file.
        """
        return self.system.get_profile_choices_for_input(
            input_file, tailoring_file
        )

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="", out_signature="a(xsi)")
    def GetAsyncActionsStatus(self):
        return self.system.async.get_status()

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="s", out_signature="(sssn)")
    def EvaluateSpecXML(self, xml_source):
        spec = EvaluationSpec()
        spec.load_from_xml_source(xml_source)
        arf, stdout, stderr, exit_code = spec.evaluate(self.system.config)
        return (arf, stdout, stderr, exit_code)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="", out_signature="ax")
    def ListTaskIDs(self):
        """Returns a list of IDs of tasks that System has loaded from config
        files.
        """
        return self.system.list_task_ids()

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xs", out_signature="")
    def SetTaskTitle(self, task_id, title):
        """Set title of existing task with given ID.

        The change is persistent after the function returns.
        """
        return self.system.set_task_title(task_id, title)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="s")
    def GetTaskTitle(self, task_id):
        """Retrieves title of task with given ID.
        """
        return self.system.get_task_title(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="s")
    def GenerateGuideForTask(self, task_id):
        """Generates and returns HTML guide for a task with given ID.
        """
        return self.system.generate_guide_for_task(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="")
    def RunTaskOutsideSchedule(self, task_id):
        """Given task will be run as soon as possible without affecting its
        schedule. This feature is useful mainly for testing purposes.
        """
        return self.system.run_task_outside_schedule(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="", out_signature="x")
    def CreateTask(self):
        """Creates a new task with empty contents, the task is created
        in a disabled state so it won't be run.

        The task is not persistent until some of its attributes are changed.
        Empty tasks are worthless, so we don't save them until they have at
        least some data.
        """
        return self.system.create_task()

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="")
    def RemoveTask(self, task_id):
        """Removes task with given ID and deletes its config file. The task has
        to be disabled, else the operation fails.

        The change is persistent after the function returns.
        """
        return self.system.remove_task(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xb", out_signature="")
    def SetTaskEnabled(self, task_id, enabled):
        """Sets enabled flag of an existing task with given ID.

        The change is persistent after the function returns.
        """
        return self.system.set_task_enabled(task_id, enabled)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="b")
    def GetTaskEnabled(self, task_id):
        """Retrieves the enabled flag of an existing task with given ID.
        """
        return self.system.get_task_enabled(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xs", out_signature="")
    def SetTaskTarget(self, task_id, target):
        """Set target of existing task with given ID.

        The change is persistent after the function returns.
        """
        return self.system.set_task_target(task_id, target)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="s")
    def GetTaskTarget(self, task_id):
        """Retrieves target of existing task with given ID.
        """
        return self.system.get_task_target(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xs", out_signature="")
    def SetTaskInput(self, task_id, input_):
        """Set input of existing task with given ID.

        input can be absolute file path or the XML source itself, this is
        is autodetected.

        The change is persistent after the function returns.
        """
        return self.system.set_task_input(
            task_id, input_ if input_ != "" else None
        )

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xs", out_signature="")
    def SetTaskTailoring(self, task_id, tailoring):
        """Set tailoring of existing task with given ID.

        tailoring can be absolute file path or the XML source itself, this is
        is autodetected.

        The change is persistent after the function returns.
        """
        return self.system.set_task_tailoring(
            task_id, tailoring if tailoring != "" else None
        )

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xs", out_signature="")
    def SetTaskProfileID(self, task_id, profile_id):
        """Set profile ID of existing task with given ID.

        The change is persistent after the function returns.
        """
        return self.system.set_task_profile_id(task_id, profile_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xb", out_signature="")
    def SetTaskOnlineRemediation(self, task_id, online_remediation):
        """Sets whether online remediation of existing task with given ID
        is enabled.

        The change is persistent after the function returns.
        """
        return self.system.set_task_online_remediation(
            task_id, online_remediation
        )

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xs", out_signature="")
    def SetTaskScheduleNotBefore(self, task_id, schedule_not_before_str):
        """Sets time when the task is next scheduled to run. The time is passed
        as a string in format YYYY-MM-DDTHH:MM in UTC with no timezone info!
        Example: 2015-05-14T13:49

        The change is persistent after the function returns.
        """
        schedule_not_before = datetime.strptime(
            schedule_not_before_str,
            "%Y-%m-%dT%H:%M"
        )

        return self.system.set_task_schedule_not_before(
            task_id, schedule_not_before
        )

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xx", out_signature="")
    def SetTaskScheduleRepeatAfter(self, task_id, schedule_repeat_after):
        """Sets number of hours after which the task should be repeated.

        For example 24 for daily tasks, 24*7 for weekly tasks, ...

        The change is persistent after the function returns.
        """

        return self.system.set_task_schedule_repeat_after(
            task_id, schedule_repeat_after
        )

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="ax")
    def GetTaskResultIDs(self, task_id):
        """Retrieves list of available task result IDs.
        """
        return self.system.get_task_result_ids(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xx", out_signature="s")
    def GetARFOfTaskResult(self, task_id, result_id):
        """Retrieves full ARF of result of given task.
        """
        return self.system.get_arf_of_task_result(task_id, result_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="x", out_signature="")
    def RemoveTaskResults(self, task_id):
        """Remove all results of given task.
        """
        return self.system.remove_task_results(task_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xx", out_signature="")
    def RemoveTaskResult(self, task_id, result_id):
        """Remove result of given task.
        """
        return self.system.remove_task_result(task_id, result_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xx", out_signature="s")
    def GetStdOutOfTaskResult(self, task_id, result_id):
        """Retrieves full stdout of result of given task.
        """
        return self.system.get_stdout_of_task_result(task_id, result_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xx", out_signature="s")
    def GetStdErrOfTaskResult(self, task_id, result_id):
        """Retrieves full stderr of result of given task.
        """
        return self.system.get_stderr_of_task_result(task_id, result_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xx", out_signature="i")
    def GetExitCodeOfTaskResult(self, task_id, result_id):
        """Retrieves exit code of result of given task.
        """
        return self.system.get_exit_code_of_task_result(task_id, result_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature="xx", out_signature="s")
    def GenerateReportForTaskResult(self, task_id, result_id):
        """Generates and returns HTML report for report of given task.
        """
        return self.system.generate_report_for_task_result(task_id, result_id)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE, in_signature='s',
                         out_signature='s')
    def inspect_container(self, cid):
        ''' Returns inspect data of a container'''
        inspect_data = self.docker_conn.inspect_container(cid)
        return json.dumps(inspect_data)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE, in_signature='s',
                         out_signature='s')
    def inspect_image(self, iid):
        ''' Returns inspect data of an image'''
        inspect_data = self.docker_conn.inspect_image(iid)
        return json.dumps(inspect_data)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE, out_signature='s')
    def images(self):
        ''''''
        images = self.docker_conn.images(all=True)
        return json.dumps(images)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE, out_signature='s')
    def containers(self):
        ''''''
        cons = self.docker_conn.containers(all=True)
        return json.dumps(cons)

    @staticmethod
    def _parse_only_cache(config, onlycache):
        if onlycache == 2:
            return not config.fetch_cve
        elif onlycache == 1:
            return True
        elif onlycache == 0:
            return False

        else:
            raise RuntimeError("Invalid value %i for onlycache" % (onlycache))

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature='bbiy', out_signature='s')
    def scan_containers(self, onlyactive, allcontainers, number, onlycache=2):
        """onlycache -
            0 to enable CVE fetch
            1 to disable CVE fetch
            2 to use defaults from oscapd config file
        """
        worker = Worker(onlyactive=onlyactive, allcontainers=allcontainers,
                        number=number,
                        onlycache=self._parse_only_cache(self.system.config, int(onlycache)),
                        fetch_cve_url=self.system.config.fetch_cve_url)
        return_json = worker.start_application()
        return json.dumps(return_json)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE, in_signature='bbiy',
                         out_signature='s')
    def scan_images(self, allimages, images, number, onlycache=2):
        """onlycache -
            0 to enable CVE fetch
            1 to disable CVE fetch
            2 to use defaults from oscapd config file
        """
        worker = Worker(allimages=allimages, images=images,
                        number=number,
                        onlycache=self._parse_only_cache(self.system.config, int(onlycache)),
                        fetch_cve_url=self.system.config.fetch_cve_url)
        return_json = worker.start_application()
        return json.dumps(return_json)

    @dbus.service.method(dbus_interface=dbus_utils.DBUS_INTERFACE,
                         in_signature='asiy', out_signature='s')
    def scan_list(self, scan_list, number, onlycache=2):
        """onlycache -
            0 to enable CVE fetch
            1 to disable CVE fetch
            2 to use defaults from oscapd config file
        """
        worker = Worker(scan=scan_list, number=number,
                        onlycache=self._parse_only_cache(self.system.config, int(onlycache)),
                        fetch_cve_url=self.system.config.fetch_cve_url)
        return_json = worker.start_application()
        return json.dumps(return_json)
