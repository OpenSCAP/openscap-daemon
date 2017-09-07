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

import argparse
import docker
import os
import shutil
import sys
import tempfile
import json
import requests


def harden(target_id, results_dir):
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

    print("Hardening target {}.".format(target_id))

    temp_dir = tempfile.mkdtemp()
    fix_script = os.path.join(results_dir, target_id, "fix.sh")

    try:
        shutil.copy(fix_script, temp_dir)
    except IOError as e:
        raise RuntimeError(
            "Can't find a remediation for given image: {}.\n"
            .format(e)
        )

    try:
        dockerfile_path = os.path.join(temp_dir, "Dockerfile")
        with open(dockerfile_path, "w") as f:
            f.write("FROM " + target_id + "\n")
            f.write("COPY fix.sh /\n")
            f.write("RUN chmod +x /fix.sh; /fix.sh\n")

        try:
            build_output_generator = client.build(
                path=temp_dir,
                # don't use image cache to ensure that original image
                # is always hardened
                nocache=True
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
            sys.stdout.write(item_dict["stream"])
            build_output.append(item_dict["stream"])
        image_id = build_output[-1].split()[-1]

        print(
            "Successfully built hardened image {} from {}.\n"
            .format(image_id, target_id)
        )
    except RuntimeError as e:
        raise RuntimeError(
            "Cannot build hardened image from {}: {}\n"
            .format(target_id, e)
        )
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Hardens container images.')
    parser.add_argument("--id", required=True,
                        help="Image ID")
    parser.add_argument("--results_dir", required=True,
                        help="Directory containing the fix.")
    args = parser.parse_args()
    try:
        harden(args.id, args.results_dir)
    except RuntimeError as e:
        sys.stderr.write(str(e))
        sys.exit(1)
