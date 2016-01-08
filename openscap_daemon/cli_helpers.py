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

import sys
import os.path
from openscap_daemon import evaluation_spec


if sys.version_info < (3,):
    py2_raw_input = raw_input
else:
    py2_raw_input = input


def print_table(table, first_row_header=True):
    """Takes given table - list of lists - and prints it as a table, using
    ASCII characters for formatting.

    The first row is formatted as a header.

    I did consider using some python package or module to do this but that
    would introduce additional dependencies. The functionality we need is simple
    enough to write it ourselves.
    """

    column_max_sizes = {}
    for row in table:
        i = 0
        for column_cell in row:
            if i not in column_max_sizes:
                column_max_sizes[i] = 0

            column_max_sizes[i] = \
                max(column_max_sizes[i], len(str(column_cell)))
            i += 1

    total_width = len(" | ".join(
        [" " * max_size for max_size in column_max_sizes.values()]
    ))

    start_row = 0

    if first_row_header:
        assert(len(table) > 0)

        print("-+-".join(
            "-" * max_size for max_size in column_max_sizes.values())
        )
        print(" | ".join(
            [str(cell).ljust(column_max_sizes[table[start_row].index(cell)])
             for cell in table[start_row]]
        ))
        print("-+-".join(
            "-" * max_size for max_size in column_max_sizes.values())
        )
        start_row += 1

    for row in table[start_row:]:
        print(" | ".join(
            [str(cell).ljust(column_max_sizes[row.index(cell)])
             for cell in row]
        ))


def cli_create_evaluation_spec(dbus_iface):
    """Interactively create EvaluationSpec and return it. Returns None if user
    cancels the action.
    """
    print("Creating EvaluationSpec interactively...")
    print("")

    try:
        target = py2_raw_input("Target (empty for localhost): ")
        if not target:
            target = "localhost"

        print("Found the following SCAP Security Guide content: ")
        ssg_choices = dbus_iface.GetSSGChoices(utf8_strings=True)
        i = 0
        for ssg_choice in ssg_choices:
            print("\t%i:  %s" % (i + 1, ssg_choice))
            i += 1

        input_file = None
        input_ssg_choice = py2_raw_input(
            "Choose SSG content by number (empty for custom content): ")
        if not input_ssg_choice:
            input_file = py2_raw_input("Input file (absolute path): ")
        else:
            input_file = ssg_choices[int(input_ssg_choice) - 1]

        input_file = os.path.abspath(input_file)

        tailoring_file = py2_raw_input(
            "Tailoring file (absolute path, empty for no tailoring): ")
        if tailoring_file in [None, ""]:
            tailoring_file = ""
        else:
            tailoring_file = os.path.abspath(tailoring_file)

        print("Found the following possible profiles: ")
        profile_choices = dbus_iface.GetProfileChoicesForInput(
            input_file, tailoring_file, utf8_strings=True
        )
        i = 0
        for key, value in profile_choices.items():
            print("\t%i:  %s (id='%s')" % (i + 1, value, key))
            i += 1

        profile_choice = py2_raw_input(
            "Choose profile by number (empty for (default) profile): ")
        if profile_choice is not None:
            profile = profile_choices.keys()[int(profile_choice) - 1]
        else:
            profile = None

        online_remediation = False
        if py2_raw_input("Online remediation (1, y or Y for yes, else no): ") in \
                ["1", "y", "Y"]:
            online_remediation = True

        ret = evaluation_spec.EvaluationSpec()
        ret.target = target
        ret.input_.set_file_path(input_file)
        if tailoring_file not in [None, ""]:
            ret.tailoring.set_file_path(tailoring_file)
        ret.profile_id = profile
        ret.online_remediation = online_remediation

        return ret

    except KeyboardInterrupt:
        return None
