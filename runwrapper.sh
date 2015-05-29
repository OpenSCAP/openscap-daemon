#!/bin/bash

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

# parent dir of this script
PARENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# add directory with "scap_client" to $PYTHONPATH
export PYTHONPATH=$PARENT_DIR:$PYTHONPATH

export SCAP_CLIENT_DATA_DIR="$PARENT_DIR/tests/data_dir_template"

if [ "x$RUNWRAPPER_NO_FORK" != "x1" ]; then
    # fork a new shell to avoid polluting the environment
    bash
fi
