#!/bin/bash

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

# parent dir of this script
PARENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# add directory with "openscap_daemon" to $PYTHONPATH
export PYTHONPATH=$PARENT_DIR:$PYTHONPATH
# force python to print using utf-8
export PYTHONIOENCODING=UTF-8

export OSCAPD_DATA_DIR="$PARENT_DIR/tests/data_dir_template"

if [ "x$RUNWRAPPER_NO_FORK" != "x1" ]; then
    # fork a new shell to avoid polluting the environment
    bash
fi
