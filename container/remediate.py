#!/usr/bin/python

# Copyright 2017 Red Hat Inc., Durham, North Carolina.
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
#
# You should have received a copy of the GNU Lesser General Public License
# along with openscap-daemon.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Jan Cerny <jcerny@redhat.com>
#   Matus Marhefka <mmarhefk@redhat.com>

import argparse
import docker
import os
import shutil
import sys
import tempfile
import json
import requests
import re
import xml.etree.ElementTree as ET


def remediate(target_id, results_dir):
    # Class docker.Client was renamed to docker.APIClient in
    # python-docker-py 2.0.0.
    try:
        client = docker.APIClient()
    except AttributeError:
        client = docker.Client()

    try:
        client.ping()
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            "The Docker daemon does not appear to be running: {}.\n"
            .format(e)
        )

    print("Remediating target {}.".format(target_id))

    temp_dir = tempfile.mkdtemp()
    fix_script = os.path.join(results_dir, target_id, "fix.sh")

    try:
        shutil.copy(fix_script, temp_dir)
    except IOError as e:
        raise RuntimeError(
            "Can't find a remediation for given image: {}.\n"
            .format(e)
        )

    # Finds a platform CPE in the ARF results file and based on it selects
    # proper package manager and its cleanup command. Applying cleanup command
    # after fix script will produce smaller images after remediation. In case
    # a platform CPE is not found in the ARF results file cleanup command is
    # left empty.
    pkg_clean_cmd = ""
    arf_results = os.path.join(results_dir, target_id, "arf.xml")
    try:
        tree = ET.parse(arf_results)
        root = tree.getroot()
    except FileNotFoundError as e:
        raise RuntimeError(e)
    try:
        ns = "http://checklists.nist.gov/xccdf/1.2"
        platform_cpe = root.find(
            ".//{%s}TestResult/{%s}platform" %(ns, ns)
        ).attrib['idref']
    except AttributeError:
        pass
    if "fedora" in platform_cpe:
        pkg_clean_cmd = "; dnf clean all"
    elif "redhat" in platform_cpe:
        try:
            distro_version = int(re.search("\d+", platform_cpe).group(0))
        except AttributeError:
            # In case it is not possible to extract rhel version, use yum.
            distro_version = 7
        if distro_version >= 8:
            pkg_clean_cmd = "; dnf clean all"
        else:
            pkg_clean_cmd = "; yum clean all"
    elif "debian" in platform_cpe:
        pkg_clean_cmd = "; apt-get clean; rm -rf /var/lib/apt/lists/*"
    elif "ubuntu" in platform_cpe:
        pkg_clean_cmd = "; apt-get clean; rm -rf /var/lib/apt/lists/*"

    try:
        dockerfile_path = os.path.join(temp_dir, "Dockerfile")
        with open(dockerfile_path, "w") as f:
            f.write("FROM " + target_id + "\n")
            f.write("COPY fix.sh /\n")
            f.write(
                "RUN chmod +x /fix.sh; /fix.sh {}\n"
                .format(pkg_clean_cmd)
            )

        try:
            build_output_generator = client.build(
                path=temp_dir,
                # don't use image cache to ensure that original image
                # is always remediated
                nocache=True,
                # remove intermediate containers spawned during build
                rm=True
            )
        except docker.errors.APIError as e:
            raise RuntimeError("Docker exception: {}\n".format(e))

        build_output = []
        for item in build_output_generator:
            item_dict = json.loads(item.decode("utf-8"))
            if "error" in item_dict:
                raise RuntimeError(
                    "Error during Docker build {}\n".format(item_dict["error"])
                )
            try:
                sys.stdout.write(item_dict["stream"])
                build_output.append(item_dict["stream"])
            except KeyError:
                # Skip empty items of build_output_generator.
                pass
        image_id = build_output[-1].split()[-1]

        print(
            "Successfully built remediated image {} from {}.\n"
            .format(image_id, target_id)
        )
    except RuntimeError as e:
        raise RuntimeError(
            "Cannot build remediated image from {}: {}\n"
            .format(target_id, e)
        )
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Remediates container images.')
    parser.add_argument("--id", required=True,
                        help="Image ID")
    parser.add_argument("--results_dir", required=True,
                        help="Directory containing the fix.")
    args = parser.parse_args()
    try:
        remediate(args.id, args.results_dir)
    except RuntimeError as e:
        sys.stderr.write(str(e))
        sys.exit(1)
