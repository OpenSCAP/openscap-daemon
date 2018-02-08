#!/usr/bin/python

import argparse
import collections
import contextlib


INDENTATION = "    "
COMMAND_DELIMITER = " \\\n{}&& ".format(INDENTATION)

labels = [
    ("com.redhat.component", "openscap-docker"),
    ("name", "openscap"),
    ("version", "testing"),
    ("architecture", "x86_64"),
    ("summary", "OpenSCAP container image that provides security/compliance scanning capabilities for 'atomic scan'"),
    ("description", "OpenSCAP is an auditing tool that utilizes the Extensible Configuration Checklist Description Format (XCCDF). XCCDF is a standard way of expressing checklist content and defines security checklists."),
    ("io.k8s.display-name", "OpenSCAP"),
    ("io.k8s.description", "OpenSCAP is an auditing tool that utilizes the Extensible Configuration Checklist Description Format (XCCDF). XCCDF is a standard way of expressing checklist content and defines security checklists."),
    ("io.openshift.tags", "security openscap scan"),
    ("install", "docker run --rm --privileged -v /:/host/ IMAGE sh /root/install.sh IMAGE"),
    ("run", "docker run -it --rm -v /:/host/ IMAGE sh /root/run.sh"),
    ("help", "docker run --rm --privileged -v /usr/bin:/usr/bin -v /var/run:/var/run -v /lib:/lib -v /lib64:/lib64 -v /etc/sysconfig:/etc/sysconfig IMAGE sh /root/help.sh IMAGE"),
]

packages = {
    "openssh-clients",
    "wget",
    "bzip2",
}

files = [
    ("container/install.sh", "/root/"),
    ("container/run.sh", "/root/"),
    ("container/openscap", "/root/"),
    ("container/config.ini", "/root/"),
    ("container/remediate.py", "/root/"),
    ("container/help.sh", "/root/"),
]
env_variables = [
    ("container", "docker")
]
download_cve_feeds_command = [
    "wget --no-verbose -P /var/lib/oscapd/cve_feeds/ "
    "https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL{5,6,7}.xml.bz2",
    "bzip2 -dk /var/lib/oscapd/cve_feeds/com.redhat.rhsa-RHEL{5,6,7}.xml.bz2",
    "ln -s /var/lib/oscapd/cve_feeds/ /var/tmp/image-scanner",
]
openscap_build_command = [
    "git clone -b maint-1.2 https://github.com/OpenSCAP/openscap.git",
    "pushd /openscap",
    "./autogen.sh",
    "./configure --enable-sce --prefix=/usr",
    "make -j 4 install",
    "popd",
]
ssg_build_command = [
    "git clone https://github.com/OpenSCAP/scap-security-guide.git",
    "pushd /scap-security-guide/build",
    "cmake -DCMAKE_INSTALL_DATADIR=/usr/share ..",
    "make -j 4 install",
    "popd",
]
daemon_local_build_command = [
    "pushd /openscap-daemon",
    "python setup.py install",
    "popd",
]


def make_parser():
    parser = argparse.ArgumentParser(description="Builds an image with OpenSCAP Daemon")

    openscap_group = parser.add_mutually_exclusive_group(required=False)
    parser.add_argument(
        "--base", type=str, default="fedora",
        help="Base image name (default is fedora)")
    openscap_group.add_argument(
        "--openscap-from-git", action="store_true",
        default=False, help="Use OpenSCAP from upstream instead of package")
    openscap_group.add_argument(
        "--openscap-from-koji", type=str,
        help="Use OpenSCAP from Koji based on build ID (Fedora only)")

    ssg_group = parser.add_mutually_exclusive_group(required=False)
    ssg_group.add_argument(
        "--ssg-from-koji", type=str,
        help="Use SCAP Security Guide from Koji based on build ID (Fedora only)")
    ssg_group.add_argument(
        "--ssg-from-git", action="store_true", default=False,
        help="Use SCAP Security Guide from upstream instead of package")

    daemon_group = parser.add_mutually_exclusive_group(required=False)
    daemon_group.add_argument(
        "--daemon-from-local", action="store_true", default=False,
        help="Use OpenSCAP Daemon from local working tree instead of package")
    daemon_group.add_argument(
        "--daemon-from-koji", type=str,
        help="Use OpenSCAP Daemon from Koji based on build ID (Fedora only)")
    return parser


def output_baseimage_line(baseimage_name):
    return "FROM {0}\n\n".format(baseimage_name)


def output_labels_lines(label_value_pairs):
    label_value_lines = [
        '{}="{}"'.format(label, value)
        for label, value in label_value_pairs]
    label_value_lines = ['LABEL'] + label_value_lines
    label_statement = " \\\n{}".format(INDENTATION).join(label_value_lines)
    return label_statement


def output_env_lines(env_value_pairs):
    envvar_value_lines = [
        '{}="{}"'.format(envvar, value)
        for envvar, value in env_value_pairs]
    envvar_value_lines = ['ENV'] + envvar_value_lines
    env_statement = " \\\n{}".format(INDENTATION).join(envvar_value_lines)
    return env_statement


def _aggregate_by_destination(src_dest_pairs):
    destinations = collections.defaultdict(set)
    for src, dest in src_dest_pairs:
        destinations[dest].add(src)
    return destinations


def _output_copy_lines_for_destination(sources, destination):
    elements = ['COPY'] + list(sources) + [destination]
    if len(sources) == 1:
        copy_statement = " ".join(elements)
    else:
        copy_statement = " \\\n{}".format(INDENTATION).join(elements)
    return copy_statement


def output_copy_lines(src_dest_pairs):
    destinations = _aggregate_by_destination(src_dest_pairs)
    copy_statements = []
    for dest, sources in destinations.items():
        statement = _output_copy_lines_for_destination(sources, dest)
        copy_statements.append(statement)
    return "\n".join(copy_statements)


class PackageEnv(object):
    def __init__(self):
        self.install_command_beginning = None
        self.remove_command_beginning = None
        self.clear_cache = None
        self.builddep_package = None
        self.builddep_command_beginning = None
        self.additional_repositories_were_enabled = False

    def _assert_class_is_complete(self):
        assert (
            self.install_command_beginning is not None
            and self.remove_command_beginning is not None
            and self.clear_cache is not None
            and self.builddep_package is not None
            and self.builddep_command_beginning is not None
        ), "The class {} is not complete, use a fully defined child."

    def install_command_element(self, packages_string):
        return "{} {}".format(self.install_command_beginning, packages_string)

    def remove_command_element(self, packages_string):
        return "{} {}".format(self.remove_command_beginning, packages_string)

    def _enable_additional_repositories_command_element(self):
        return []

    def get_enable_additional_repositories_command_element(self):
        if not self.additional_repositories_were_enabled:
            return self._enable_additional_repositories_command_element()
        else:
            return []
        self.additional_repositories_were_enabled = True

    def _get_install_commands(self, packages_string):
        self._assert_class_is_complete()
        commands = self.get_enable_additional_repositories_command_element()
        commands.append(self.install_command_element(packages_string))
        return commands

    @contextlib.contextmanager
    def install_then_clean_all(self, packages_string):
        commands = self._get_install_commands(packages_string)
        yield commands
        commands.append(self.clear_cache)

    @contextlib.contextmanager
    def install_then_remove(self, packages_string, clear_cache_afterwards=False):
        commands = self._get_install_commands(packages_string)
        yield commands
        commands.append(self.remove_command_element(packages_string))
        if clear_cache_afterwards:
            commands.append(self.clear_cache)


class RhelEnv(PackageEnv):
    def __init__(self):
        super(RhelEnv, self).__init__()
        self.install_command_beginning = "yum install -y"
        self.remove_command_beginning = "yum remove -y"
        self.clear_cache = "yum clean all"
        self.builddep_command_beginning = "yum-builddep -y"
        self.builddep_package = "yum-utils"

    def _enable_additional_repositories_command_element(self):
        commands = super(RhelEnv, self)._enable_additional_repositories_command_element()
        commands.append(
            "rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm")
        return commands


class FedoraEnv(PackageEnv):
    def __init__(self):
        super(FedoraEnv, self).__init__()
        self.install_command_beginning = "dnf install -y"
        self.remove_command_beginning = "dnf remove -y"
        self.clear_cache = "dnf clean all"
        self.builddep_command_beginning = "dnf -y builddep"
        self.builddep_package = "'dnf-command(builddep)'"


def choose_pkg_env_class(baseimage):
    if baseimage.startswith("fedora"):
        return FedoraEnv
    else:
        return RhelEnv


class TasksRecorder(object):
    def __init__(self, builddep_package):
        self.builddep_package = builddep_package

        self._build_from_source = []
        self._build_commands = []

        self._install_from_koji = []
        self._koji_commands = []

    def merge(self, rhs):
        self._build_from_source.extend(rhs._build_from_source)
        self._build_commands.extend(rhs._build_commands)
        self._koji_commands.extend(rhs._koji_commands)
        self._install_from_koji.extend(rhs._install_from_koji)

    def build_from_source(self, what, how=None):
        packages.add(self.builddep_package)

        self._build_from_source.append(what)
        if how is not None:
            self._build_commands.extend(how)

    def install_from_koji(self, what, how=None):
        self._install_from_koji.append(what)
        if how is not None:
            self._koji_commands.extend(how)

    def install_build_deps(self, builddep_command):
        if len(self._build_from_source) == 0:
            return []
        build_deps_string = " ".join(self._build_from_source)
        command = "{0} {1}".format(builddep_command, build_deps_string)
        return [command]

    def add_commands_for_building_from_custom_sources(self):
        return self._build_commands

    def add_koji_commands(self):
        return self._koji_commands


def decide_about_getting_openscap(args, pkg_env):
    tasks = TasksRecorder(pkg_env.builddep_package)
    if args.openscap_from_git:
        packages.update({"git", "libtool", "automake"})
        tasks.build_from_source("openscap", openscap_build_command)
    elif args.openscap_from_koji is not None:
        packages.add("koji")
        openscap_koji_command = [
            "koji download-build -a x86_64 {0}".format(args.openscap_from_koji),
            "koji download-build -a noarch {0}".format(args.openscap_from_koji),
            pkg_env.install_command_element(
               "openscap-[0-9]*.rpm openscap-scanner*.rpm "
               "openscap-utils*.rpm openscap-containers*.rpm"),
            "rm -f openscap-*.rpm",
        ]
        tasks.install_from_koji("openscap", openscap_koji_command)
    else:
        packages.add("openscap-utils")

    return tasks


def decide_about_getting_ssg(args, pkg_env):
    tasks = TasksRecorder(pkg_env.builddep_package)
    if args.ssg_from_git:
        packages.add("git")
        tasks.build_from_source("scap-security-guide", ssg_build_command)
    elif args.ssg_from_koji is not None:
        packages.add("koji")
        ssg_koji_command = [
            "koji download-build -a noarch {0}".format(args.ssg_from_koji),
            pkg_env.install_command_element("scap-security-guide-[0-9]*.rpm"),
            "rm -f scap-security-guide*.rpm",
        ]
        tasks.install_from_koji("scap-security-guide", ssg_koji_command)
    else:
        packages.add("scap-security-guide")

    return tasks


def decide_about_getting_openscap_daemon(args, pkg_env):
    tasks = TasksRecorder(pkg_env.builddep_package)
    if args.daemon_from_local:
        tasks.build_from_source("openscap-daemon", daemon_local_build_command)
        files.append((".", "/openscap-daemon/"))
    elif args.daemon_from_koji is not None:
        packages.add("koji")
        daemon_koji_command = [
            "koji download-build -a noarch {0}".format(args.daemon_from_koji),
            pkg_env.install_command_element("openscap-daemon*.rpm"),
            "rm -f openscap-daemon*.rpm",
        ]
        tasks.install_from_koji("openscap-daemon", daemon_koji_command)
    else:
        packages.add("openscap-daemon")

    return tasks


def output_run_directive(commands):
    commands_string = COMMAND_DELIMITER.join(["true"] + commands + ["true"])
    return "RUN {}\n\n".format(commands_string)


def main():
    parser = make_parser()
    args = parser.parse_args()
    pkg_env = choose_pkg_env_class(args.base)()

    if (not isinstance(pkg_env, FedoraEnv)) and (
            args.openscap_from_koji is not None
            or args.ssg_from_koji is not None
            or args.daemon_from_koji is not None):
        parser.error("Koji builds can be used only with fedora base image")

    with open("Dockerfile", "w") as f:
        # write out the Dockerfile
        f.write(output_baseimage_line(args.base))

        f.write(output_labels_lines(labels))
        f.write("\n\n")

        f.write(output_env_lines(env_variables))
        f.write("\n\n")

        install_steps = decide_about_getting_openscap(args, pkg_env)
        install_steps.merge(decide_about_getting_ssg(args, pkg_env))
        install_steps.merge(decide_about_getting_openscap_daemon(args, pkg_env))

        # inject files
        f.write(output_copy_lines(files))
        f.write("\n\n")

        run_commands = []

        packages_string = " ".join(packages)
        with pkg_env.install_then_clean_all(packages_string) as commands:
            commands.extend(
                install_steps.install_build_deps(pkg_env.builddep_command_beginning))

            commands.extend(
                install_steps.add_commands_for_building_from_custom_sources())

            commands.extend(
                install_steps.add_koji_commands())

        run_commands.extend(commands)
        f.write(output_run_directive(run_commands))

        f.write(output_run_directive(download_cve_feeds_command))

        # add CMD instruction to the Dockerfile, including a comment
        f.write("# It doesn't matter what is in the line below, atomic will change the CMD\n")
        f.write("# before running it\n")
        f.write('CMD ["/root/run.sh"]\n')


if __name__ == "__main__":
    main()
