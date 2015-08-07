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
        [" " * max_size for max_size in column_max_sizes.itervalues()]
    ))

    start_row = 0

    if first_row_header:
        assert(len(table) > 0)

        print("-+-".join(
            "-" * max_size for max_size in column_max_sizes.itervalues())
        )
        print(" | ".join(
            [str(cell).ljust(column_max_sizes[table[start_row].index(cell)])
             for cell in table[start_row]]
        ))
        print("-+-".join(
            "-" * max_size for max_size in column_max_sizes.itervalues())
        )
        start_row += 1

    for row in table[start_row:]:
        print(" | ".join(
            [str(cell).ljust(column_max_sizes[row.index(cell)])
             for cell in row]
        ))
