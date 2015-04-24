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


import dbus
import dbus.service
import gobject


class SCAPClientDbus(dbus.service.Object):
    def __init__(self, bus, object_path):
        super(SCAPClientDbus, self).__init__(bus, object_path)

    @dbus.service.method(dbus_interface="org.OpenSCAP.SCAPClientInterface",
                         in_signature="", out_signature="s")
    def GreetMe(self):
        return "Hello!"


def main():
    import dbus.mainloop.glib
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    # bus = dbus.SystemBus()
    # for easier testing
    bus = dbus.SessionBus()
    name = dbus.service.BusName("org.OpenSCAP.SCAPClient", bus)
    obj = SCAPClientDbus(bus, "/SCAPClient")

    loop = gobject.MainLoop()
    loop.run()


if __name__ == "__main__":
    main()
