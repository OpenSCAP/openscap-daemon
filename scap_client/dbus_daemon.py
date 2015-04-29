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

from scap_client import System

import dbus
import dbus.service
import gobject
import threading

OBJECT_PATH = "/SCAPClient"
DBUS_INTERFACE = "org.OpenSCAP.SCAPClientInterface"
BUS_NAME = "org.OpenSCAP.SCAPClient"

# Internal note: Python does not support unsigned long integer while dbus does,
# to avoid weird issues I just use 64bit integer in the interface signatures.
# "2^63-1 IDs should be enough for everyone."


class SCAPClientDbus(dbus.service.Object):
    def __init__(self, bus, data_dir_path):
        super(SCAPClientDbus, self).__init__(bus, OBJECT_PATH)

        self.system = System(data_dir_path)
        self.system.load_tasks()

        self.system_worker_thread = threading.Thread(
            target=lambda: self.system.update_worker()
        )
        self.system_worker_thread.daemon = True
        self.system_worker_thread.start()

    @dbus.service.method(dbus_interface=DBUS_INTERFACE,
                         in_signature="", out_signature="s")
    def GreetMe(self):
        """Testing method. Don't expect it to be useful.
        """
        return "Hello!"

    @dbus.service.method(dbus_interface=DBUS_INTERFACE,
                         in_signature="", out_signature="ax")
    def ListTaskIDs(self):
        """Returns a list of IDs of tasks that System has loaded from config
        files.
        """
        return self.system.list_task_ids()

    @dbus.service.method(dbus_interface=DBUS_INTERFACE,
                         in_signature="x", out_signature="s")
    def GetTaskTitle(self, task_id):
        """Retrieves title of task with given ID.
        """
        return self.system.get_task_title(task_id)

    @dbus.service.method(dbus_interface=DBUS_INTERFACE,
                         in_signature="x", out_signature="s")
    def GenerateGuideForTask(self, task_id):
        """Generates and returns HTML guide for a task with given ID.
        """
        return self.system.generate_guide_for_task(task_id)

    @dbus.service.method(dbus_interface=DBUS_INTERFACE,
                         in_signature="xx", out_signature="s")
    def GenerateReportForTaskResult(self, task_id, result_id):
        """Generates and returns HTML report for report of given task.
        """
        return self.system.generate_report_for_task_result(task_id, result_id)


def main():
    gobject.threads_init()

    import dbus.mainloop.glib
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    # bus = dbus.SystemBus()
    # for easier testing
    bus = dbus.SessionBus()
    name = dbus.service.BusName(BUS_NAME, bus)
    # TODO: hardcoded path
    obj = SCAPClientDbus(bus, "../tests/data_dir_template")

    loop = gobject.MainLoop()
    loop.run()


if __name__ == "__main__":
    main()
