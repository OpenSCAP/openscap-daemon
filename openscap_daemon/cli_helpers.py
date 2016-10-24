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
import logging
from openscap_daemon import evaluation_spec
from xml.etree import cElementTree as ElementTree

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
        for i, column_cell in enumerate(row):
            if i not in column_max_sizes:
                column_max_sizes[i] = 0

            column_max_sizes[i] = \
                max(column_max_sizes[i], len(str(column_cell)))

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
        ssg_choices = dbus_iface.GetSSGChoices()
        for i, ssg_choice in enumerate(ssg_choices):
            print("\t%i:  %s" % (i + 1, ssg_choice))

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
            input_file, tailoring_file
        )
        for i, (key, value) in enumerate(profile_choices.items()):
            print("\t%i:  %s (id='%s')" % (i + 1, value, key))

        profile_choice = py2_raw_input(
            "Choose profile by number (empty for (default) profile): ")
        if profile_choice is not None:
            profile = list(profile_choices.keys())[int(profile_choice) - 1]
        else:
            profile = None

        online_remediation = False
        if py2_raw_input("Online remediation (1, y or Y for yes, else no): ") \
                in ["1", "y", "Y"]:
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


def preprocess_targets(targets, output_dir_map):
    """The main goal of this function is to expand chroots-in-dir:// to a list
    of chroot:// targets. chroots-in-dir is a convenience function that the rest
    of the OpenSCAP-daemon API doesn't know about.

    The output_dir_map maps the processed targets to directories from
    chroots-in-dir expansion.
    """

    ret = []

    for target in targets:
        if target.startswith("chroots-in-dir://"):
            logging.debug("Expanding target '%s'...", target)

            dir_ = os.path.abspath(target[len("chroots-in-dir://"):])
            for chroot in os.listdir(dir_):
                full_path = os.path.abspath(os.path.join(dir_, chroot))

                if not os.path.isdir(full_path):
                    continue

                expanded_target = "chroot://" + full_path
                logging.debug(" ... '%s'", expanded_target)
                ret.append(expanded_target)
                output_dir_map[expanded_target] = chroot

            logging.debug("Finished expanding target '%s'.", target)

        else:
            ret.append(target)

    return ret


def summarize_cve_results(oval_source, result_list):
    """Takes given OVAL source, assuming it is CVE feed OVAL results source,
    and parses it. Each definition that has result 'true' is added to
    result_list.

    This is used to produce JSON output for atomic scan in
    `oscapd-evaluate scan`.
    """

    namespaces = {
        "ovalres": "http://oval.mitre.org/XMLSchema/oval-results-5",
        "ovaldef": "http://oval.mitre.org/XMLSchema/oval-definitions-5"
    }

    oval_root = ElementTree.fromstring(oval_source.encode("utf-8"))

    for result in oval_root.findall(
            "ovalres:results/ovalres:system/"
            "ovalres:definitions/*[@result='true']",
            namespaces):
        definition_id = result.get("definition_id")
        assert(definition_id is not None)

        definition_meta = oval_root.find(
            "./ovaldef:oval_definitions/ovaldef:definitions/*[@id='%s']/"
            "ovaldef:metadata" % (definition_id),
            namespaces
        )
        assert(definition_meta is not None)

        title = definition_meta.find("ovaldef:title", namespaces)
        # there can only be one RHSA per definition
        rhsa = definition_meta.find("ovaldef:reference[@source='RHSA']",
                                    namespaces)
        # there can be one or more CVEs per definition
        cves = definition_meta.findall("ovaldef:reference[@source='CVE']",
                                       namespaces)
        description = definition_meta.find("ovaldef:description", namespaces)
        severity = definition_meta.find("ovaldef:advisory/ovaldef:severity",
                                        namespaces)

        result_json = {}
        result_json["Title"] = title.text if title is not None else "unknown"
        result_json["Description"] = \
            description.text if description is not None else "unknown"
        result_json["Severity"] = \
            severity.text if severity is not None else "unknown"

        custom = {}
        if rhsa is not None:
            custom["RHSA ID"] = rhsa.get("ref_id", "unknown")
            custom["RHSA URL"] = rhsa.get("ref_url", "unknown")

        if len(cves) > 0:
            custom["Associated CVEs"] = []

            for cve in cves:
                custom["Associated CVEs"].append(
                    {"CVE ID": cve.get("ref_id", "unknown"),
                     "CVE URL": cve.get("ref_url", "unknown")}
                )

        result_json["Custom"] = custom

        result_list.append(result_json)


def summarize_standard_compliance_results(arf_source, result_list):
    """Takes given ARF XML source and parses it. Each Rule that doesn't have
    result 'pass', 'fixed', 'informational', 'notselected' or 'notapplicable'
    is added to result_list.

    This is used to produce JSON output for atomic scan in
    `oscapd-evaluate scan`.
    """

    namespaces = {
        "cdf": "http://checklists.nist.gov/xccdf/1.2",
    }

    arf_root = ElementTree.fromstring(arf_source.encode("utf-8"))

    test_result = arf_root.find(
        ".//cdf:TestResult[@id='%s']" %
        ("xccdf_org.open-scap_testresult_xccdf_org.ssgproject.content_profile_"
         "standard"), namespaces
    )

    benchmark = arf_root.find(".//cdf:Benchmark", namespaces)

    for rule_result in test_result.findall("./cdf:rule-result", namespaces):
        result = rule_result.find("cdf:result", namespaces).text

        if result in ["pass", "fixed", "informational", "notselected",
                      "notapplicable"]:
            continue

        rule_id = rule_result.get("idref")
        assert(rule_id is not None)

        rule = benchmark.find(".//cdf:Rule[@id='%s']" % (rule_id), namespaces)
        assert(rule is not None)

        title = rule.find("cdf:title", namespaces)
        description = rule.find("cdf:description", namespaces)
        severity = rule.get("severity", "Unknown")
        if severity in "low":
            severity = "Low"
        elif severity == "medium":
            severity = "Moderate"
        elif severity == "high":
            severity = "Important"
        else:  # "info", a valid XCCDF severity falls here
            severity = "Unknown"

        result_json = {}
        result_json["Title"] = title.text if title is not None else "unknown"
        result_json["Description"] = \
            description.text if description is not None else "unknown"
        result_json["Severity"] = severity
        result_json["Custom"] = {"XCCDF result": result}

        result_list.append(result_json)
