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
#   Mario Vazquez <mavazque@redhat.com>

import threading
import json
import os

from datetime import datetime
from flask import Flask, request


class OpenSCAPRestApi(object):
    """Internal class that implements the REST API using Flask"""
    def __init__(self, system_instance):
        super(OpenSCAPRestApi, self).__init__()

        self.app = Flask(__name__)
        self.system = system_instance

        if self.system.config.api_enabled:
            self.system.load_tasks()

            self.api_worker_thread = threading.Thread(
                target=lambda: self.run()
            )
            self.api_worker_thread.daemon = True
            self.api_worker_thread.start()

    def run(self):
        """Configures API Endpoints and runs the flask app"""
        self.app.add_url_rule("/tasks/",
                              "get_all_tasks", self.get_task,
                              methods=['GET'])
        self.app.add_url_rule("/tasks/<int:task_id>/",
                              "get_task", self.get_task,
                              methods=['GET'])
        self.app.add_url_rule("/tasks/",
                              "new_task", self.new_task,
                              methods=['POST'])
        self.app.add_url_rule("/tasks/<int:task_id>/",
                              "update_task", self.update_task,
                              methods=['PUT'])
        self.app.add_url_rule("/tasks/<int:task_id>/guide/",
                              "get_task_guide", self.get_task_guide,
                              methods=['GET'])
        self.app.add_url_rule("/tasks/<int:task_id>/result/<int:result_id>/",
                              "get_task_result", self.get_task_result,
                              methods=['GET'])
        self.app.add_url_rule("/tasks/<int:task_id>/result/",
                              "remove_all_task_results", self.remove_task_result,
                              methods=['DELETE'])
        self.app.add_url_rule("/tasks/<int:task_id>/result/<int:result_id>/",
                              "remove_task_result", self.remove_task_result,
                              methods=['DELETE'])
        self.app.add_url_rule("/tasks/<int:task_id>/run/",
                              "run_task_outside_schedule", self.run_task_outside_schedule,
                              methods=['GET'])
        self.app.add_url_rule("/tasks/<int:task_id>/",
                              "remove_task", self.remove_task,
                              methods=['DELETE'])
        self.app.add_url_rule("/tasks/<int:task_id>/results/",
                              "remove_task_and_results", self.remove_task,
                              methods=['DELETE'], defaults={'remove_results': True})
        self.app.add_url_rule("/tasks/<int:task_id>/<string:schedule>/",
                              "task_schedule", self.task_schedule,
                              methods=['PUT'])
        self.app.add_url_rule("/ssgs",
                              "get_ssg", self.get_ssg,
                              methods=['GET', 'POST'])
        if self.system.config.api_debug:
            self.app.debug = True

        self.app.run(
            host=str(self.system.config.api_host),
            port=int(self.system.config.api_port),
            use_reloader=False
        )

    def get_ssg(self, ssg_file="system", tailoring_file=None):
        """Returns a list of SSG with its profiles"""
        if request.method == "POST":
            content = request.get_json(silent=True)
            required_fields = {'ssgFile', 'tailoringFile'}
            if content is None:
                return '{"Error" : "json data required"}', 400
            elif not required_fields <= set(content):
                return '{"Error": "There are missing fields in the request"}', 400
            elif content['ssgFile'] == "":
                return '{"Error": "ssgFile field cannot be empty"}', 400
            else:
                ssg_file = content['ssgFile']
                if content['tailoringFile']:
                    tailoring_file = content['tailoringFile']
        if ssg_file == "system":
            ssg_choices = self.system.get_ssg_choices()
        else:
            ssg_choices = [ssg_file]
        ssgs = []
        for ssg_choice in ssg_choices:
            ssg_file = os.path.abspath(ssg_choice)
            if tailoring_file is None:
                tailoring_file = ""
            else:
                tailoring_file = os.path.abspath(tailoring_file)
            profiles = self.system.get_profile_choices_for_input(ssg_file, tailoring_file)
            ssg_profile = []
            if len(profiles) > 0:
                for profile_id, profile_name in profiles.items():
                    ssg_profile.append({'profileId': profile_id, 'profileName': profile_name})
                ssgs.append({'ssgFile': ssg_file, 'tailoringFile': tailoring_file, 'profiles': ssg_profile})
            else:
                ssgs.append({'ssgFile': ssg_file, 'tailoringFile': tailoring_file, 'profiles': 'Either ssgFile or tailoringFile does not exists'})
        ssgs_json = '{"ssgs":' + json.dumps(ssgs, indent=4) + '}'
        return ssgs_json

    def task_schedule(self, task_id, schedule):
        """Updates the task schedule"""
        status = []
        if schedule == "enable":
            self.system.set_task_enabled(task_id, True)
        elif schedule == "disable":
            self.system.set_task_enabled(task_id, False)
        else:
            schedule = "not_modified"
        status.append({'id': task_id, 'schedule': schedule})
        schedule_json = '{"tasks":' + json.dumps(status, indent=4) + '}'
        return schedule_json

    def remove_task(self, task_id, remove_results=False):
        """Removes tasks from OpenSCAP Daemon"""
        delete = []
        try:
            task_enabled = self.system.get_task_enabled(task_id)
            if task_enabled:
                delete.append({'id': task_id, 'removed': 'enabled tasks cannot be deleted'})
            else:
                self.system.remove_task(task_id, remove_results)
                delete.append({'id': task_id, 'removed': 'true'})
        except RuntimeError as err:
            delete.append({'id': task_id, 'removed': str(err)})
        except KeyError:
            delete.append({'id': task_id, 'removed': 'task not found'})
        remove_json = '{"tasks":' + json.dumps(delete, indent=4) + '}'
        return remove_json

    def run_task_outside_schedule(self, task_id):
        """Forces the launch of tasks"""
        run = []
        try:
            task_enabled = self.system.get_task_enabled(task_id)
            if task_enabled:
                try:
                    self.system.run_task_outside_schedule(task_id)
                    run.append({'id': task_id, 'running': 'true'})
                except RuntimeError as err:
                    run.append({'id': task_id, 'running': str(err)})
            else:
                run.append({'id': task_id, 'running': 'Task must be enabled first'})
        except KeyError:
            return '{"Error" : "Task not found"}'
        run_json = '{"tasks": ' + json.dumps(run, indent=4) + '}'
        return run_json

    def remove_task_result(self, task_id, result_id="all"):
        """Removes task results from tasks"""
        remove = []
        task_results = []
        if result_id == "all":
            self.system.remove_task_results(task_id)
        else:
            self.system.remove_task_result(task_id, result_id)
        task_results.append({'taskResultId': str(result_id), 'removed': 'true'})
        remove.append({'id': str(task_id), 'taskResultsRemoved': task_results})
        remove_json = '{"tasks": ' + json.dumps(remove, indent=4) + '}'
        return remove_json

    def get_task_result(self, task_id, result_id):
        """Returns the task Result information in html format"""
        result_html = None
        try:
            result_html = self.system.generate_report_for_task_result(task_id, result_id)
        except (RuntimeError, KeyError):
            result_html = '{"Error" : "HTML Report could not been generated. Please, check that task and result ids exists"}'
        return result_html

    def get_task_guide(self, task_id):
        """Returns the task Guide information in html format"""
        guide_html = None
        try:
            guide_html = self.system.generate_guide_for_task(task_id)
        except (RuntimeError, KeyError):
            guide_html = '{"Error" : "HTML Guide could not been generated. Please, check that task id exists"}'
        return guide_html

    def update_task(self, task_id):
        """Updates an existing task on OpenSCAP Daemon"""
        content = request.get_json(silent=True)
        required_fields = {'taskTitle', 'taskTarget', 'taskSSG', 'taskTailoring',
                           'taskProfileId', 'taskOnlineRemediation', 'taskScheduleNotBefore',
                           'taskScheduleRepeatAfter'}
        if content is None:
            return '{"Error" : "json data required"}', 400
        elif not required_fields <= set(content):
            return '{"Error": "There are missing fields in the request"}', 400
        else:
            task_title = content['taskTitle']
            task_target = content['taskTarget']
            task_ssg = content['taskSSG']
            task_tailoring = content['taskTailoring']
            task_profile_id = content['taskProfileId']
            task_online_remediation = content['taskOnlineRemediation']
            task_schedule_not_before = content['taskScheduleNotBefore']
            task_schedule_repeat_after = content['taskScheduleRepeatAfter']
            task = []
            try:
                enabled = self.system.get_task_enabled(task_id)
                if task_title != "":
                    self.system.set_task_title(task_id, str(task_title))
                if task_target != "":
                    self.system.set_task_target(task_id, task_target)
                if task_ssg != "":
                    self.system.set_task_input(task_id, task_ssg if task_ssg != "" else None)
                if task_tailoring != "":
                    self.system.set_task_tailoring(task_id, task_tailoring if task_tailoring != "" else None)
                if task_profile_id != "":
                    self.system.set_task_profile_id(task_id, task_profile_id)
                if task_online_remediation != "":
                    if task_online_remediation not in [1, "y", "Y", "yes"]:
                        task_online_remediation = False
                    self.system.set_task_online_remediation(task_id, task_online_remediation)
                if task_schedule_not_before != "":
                    try:
                        task_schedule_not_before = datetime.strptime(task_schedule_not_before,
                                                                     "%Y-%m-%d %H:%M")
                    except ValueError:
                        task_schedule_not_before_now = datetime.now().strftime("%Y-%m-%d %H:%M")
                        task_schedule_not_before = datetime.strptime(task_schedule_not_before_now,
                                                                     "%Y-%m-%d %H:%M")
                    self.system.set_task_schedule_not_before(task_id, task_schedule_not_before)
                if task_schedule_repeat_after != "":
                    if task_schedule_repeat_after == "@daily":
                        task_schedule_repeat_after = 1 * 24
                    elif task_schedule_repeat_after == "@weekly":
                        task_schedule_repeat_after = 7 * 24
                    elif task_schedule_repeat_after == "@monthly":
                        task_schedule_repeat_after = 30 * 24
                    else:
                        task_schedule_repeat_after = 0
                    self.system.set_task_schedule_repeat_after(task_id, task_schedule_repeat_after)
                task.append({'id': str(task_id), 'enabled': enabled, 'updated': 'true'})
            except KeyError:
                return '{"Error" : "Task not found"}'
            update_json = '{"tasks":' + json.dumps(task, indent=4) + '}'
            return update_json

    def new_task(self):
        """Creates a new task on OpenSCAP Daemon"""
        content = request.get_json(silent=True)
        required_fields = {'taskTitle', 'taskTarget', 'taskSSG', 'taskTailoring',
                           'taskProfileId', 'taskOnlineRemediation', 'taskScheduleNotBefore',
                           'taskScheduleRepeatAfter'}
        if content is None:
            return '{"Error" : "json data required"}', 400
        elif not required_fields <= set(content):
            return '{"Error": "There are missing fields in the request"}', 400
        elif content['taskSSG'] == "" or content['taskProfileId'] == "":
            return '{"Error": "Both taskSSG and taskProfileId fields cannot be empty"}', 400
        else:
            task_title = content['taskTitle']
            task_target = content['taskTarget']
            task_ssg = content['taskSSG']
            task_tailoring = content['taskTailoring']
            task_profile_id = content['taskProfileId']
            task_online_remediation = content['taskOnlineRemediation']
            task_schedule_not_before = content['taskScheduleNotBefore']
            task_schedule_repeat_after = content['taskScheduleRepeatAfter']

            if task_target == "":
                task_target = "localhost"

            if task_online_remediation not in [1, "y", "Y", "yes"]:
                task_online_remediation = False

            if task_schedule_not_before == "":
                task_schedule_not_before_now = datetime.now().strftime("%Y-%m-%d %H:%M")
                task_schedule_not_before = datetime.strptime(task_schedule_not_before_now,
                                                             "%Y-%m-%d %H:%M")
            else:
                try:
                    task_schedule_not_before = datetime.strptime(task_schedule_not_before,
                                                                 "%Y-%m-%d %H:%M")
                except ValueError:
                    return '{"Error" : "Invalid taskScheduleNotBefore format. Please use %Y-%m-%d %H:%M format"}'

            if task_schedule_repeat_after == "":
                task_schedule_repeat_after = 0
            elif task_schedule_repeat_after == "@daily":
                task_schedule_repeat_after = 1 * 24
            elif task_schedule_repeat_after == "@weekly":
                task_schedule_repeat_after = 7 * 24
            elif task_schedule_repeat_after == "@monthly":
                task_schedule_repeat_after = 30 * 24
            else:
                task_schedule_repeat_after = 0

            task_id = self.system.create_task()
            self.system.set_task_title(task_id, str(task_title))
            self.system.set_task_target(task_id, task_target)
            self.system.set_task_input(task_id, task_ssg if task_ssg != "" else None)
            self.system.set_task_tailoring(task_id, task_tailoring if task_tailoring != "" else None)
            self.system.set_task_profile_id(task_id, task_profile_id)
            self.system.set_task_online_remediation(task_id, task_online_remediation)
            self.system.set_task_schedule_not_before(task_id, task_schedule_not_before)
            self.system.set_task_schedule_repeat_after(task_id, task_schedule_repeat_after)
            task = [{'id' : task_id, 'enabled' : '0'}]
            create_json = '{"tasks":' + json.dumps(task, indent=4) + '}'
            return create_json, 201

    def get_task(self, task_id="all"):
        """Returns a list of task registered on OpenSCAP Daemon"""
        if task_id == "all":
            task_ids = self.system.list_task_ids()
        else:
            task_ids = [task_id]
        tasks = []
        for task in task_ids:
            try:
                title = self.system.get_task_title(task)
                target = self.system.get_task_target(task)
                modified_timestamp = self.system.get_task_modified_timestamp(task)
                modified = datetime.fromtimestamp(modified_timestamp)
                enabled = self.system.get_task_enabled(task)
                task_results_ids = self.system.get_task_result_ids(task)
                task_results = []
                for task_result_id in task_results_ids:
                    exit_code = self.system.get_exit_code_of_task_result(task, task_result_id)
                    timestamp = self.system.get_task_result_created_timestamp(task, task_result_id)
                    # Exit code 0 means evaluation was successful and machine is compliant.
                    # Exit code 1 means there was an error while evaluating.
                    # Exit code 2 means there were no errors but the machine is not compliant.
                    if exit_code == 0:
                        status = "Compliant"
                    elif exit_code == 1:
                        status = "Non-Compliant"
                    elif exit_code == 2:
                        status = "Evaluation Error"
                    else:
                        status = "Unknow status for exit_code " + exit_code
                    task_results.append({'taskResultId': str(task_result_id), 'taskResulttimestamp': timestamp, 'taskResultStatus': status})
                tasks.append({'id': str(task), 'title': title, 'target': target, 'modified': str(modified), 'enabled': enabled, 'results': task_results})
            except KeyError:
                return '{"Error" : "Task not found"}'
        tasks_json = '{"tasks":' + json.dumps(tasks, indent=4) + '}'
        return tasks_json
