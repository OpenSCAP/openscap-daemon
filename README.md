# OpenSCAP-daemon
> Continuously evaluate your infrastructure for *SCAP* compliance!
> Avoid copying big SCAP files around, avoid having to type long IDs, avoid
> writing ad-hoc bash scripts to solve your compliance needs!

## Project Description
OpenSCAP-daemon is a service that performs SCAP scans of bare-metal machines,
virtual machines and containers. These scans can be either one-shot or
continuous according to a schedule. You can interact with the service
using the provided oscapd-cli tool or via the DBus interface.

## Motivation
The [OpenSCAP](http://open-scap.org) project has progressed greatly over the
past years and now provides very nice tooling to perform solicited one-off
*SCAP* evaluation of the machine it runs on. Unsolicited, continuous or
planned evaluation has always been out of scope of *OpenSCAP* to avoid feature
creep. The previously mentioned use-case is very desirable and has been
requested many times. We feel that now the time is right to start a project
that **helps you run oscap** and **does evaluation for you**. *OpenSCAP-daemon*
is such a project.

The project currently comprises of two parts, the **daemon** that runs in the
background sleeping until a task needs processing, and the **command-line tool**
that talks to the aforementioned daemon using *dbus*. Do not be alarmed, the
**command-line tool** is much easier to use than pure `oscap` for common
use-cases.

## Features
* *SCAP* evaluation of the following assets using
  [OpenSCAP](http://open-scap.org) -- a **NIST-certified** scanner
  * **local machine** -- `oscap`
  * **remote machine** -- `oscap-ssh`
  * **virtual machine** -- `oscap-vm`
  * **container** -- `oscap-docker`
* flexible task definition and planning
  * use any valid *SCAP* content -- for example
    [SCAP Security Guide](http://github.com/OpenSCAP/scap-security-guide),
    [NIST USGCB](http://usgcb.nist.gov/), or even
    [RHSA OVAL](https://www.redhat.com/security/data/oval/)
  * evaluate *daily*, *weekly*, *monthly* or in custom intervals
  * evaluate on demand
* parallel task processing
* results storage -- query ARFs of past results, generate HTML reports, get
  `oscap` stdout/stderr and exit codes
* command-line interface
* *dbus* *API*
* fully automated CVE evaluation of containers using OpenSCAP and Atomic.mount
* *Cockpit* integration (planned)

## Key Goals & Design Decisions
We have learned many important lessons when developing the lower layers of the
*SCAP* evaluation stack that we want to address in this project.

- **useful defaults** -- just pressing *Enter* and not providing any details
  should still yield a valid setup
- **simplicity** -- we avoid *RDBMS* and instead use features of the filesystem
- **datastreams** -- *SDS* (source datastream) and *ARF* (results datastream)
  are both  used as primary data formats for maximum compatibility between
  various tools
- **interactive CLI** -- the CLI should be as interactive as possible, user
  shouldn't need to type any IDs or other lengthy options

## Example Use-Cases

### Scan a container or container image on Atomic Host
Atomic host can use the functionality in OpenSCAP-Daemon to perform vulnerability
scans of containers and container images using the `atomic scan` command.

To use this functionality, install atomic. Then install openscap-daemon either
in standalone mode or as a SPC container image. When the daemon is running
the `atomic scan` functionality is available.

### Scan all containers or all contaner images on Atomic Host
The `atomic scan` command has command-line arguments --images, --containers and
--all that scan all images, all container and everything respectively.

### Scan local machine every day at 1:00 AM UTC
OpenSCAP-daemon thinks in terms of tasks. Let us first define the task we want
to perform:
```bash
# interactively create a new task
oscapd-cli task-create -i
Creating new task in interactive mode
Title: Daily USGCB
Target (empty for localhost): 
Found the following SCAP Security Guide content: 
        1:  /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml
        2:  /usr/share/xml/scap/ssg/content/ssg-firefox-ds.xml
        3:  /usr/share/xml/scap/ssg/content/ssg-java-ds.xml
        4:  /usr/share/xml/scap/ssg/content/ssg-rhel6-ds.xml
        5:  /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
Choose SSG content by number (empty for custom content): 4
Tailoring file (absolute path, empty for no tailoring): 
Found the following possible profiles:
        1:  CSCF RHEL6 MLS Core Baseline (id='xccdf_org.ssgproject.content_profile_CSCF-RHEL6-MLS')
        2:  United States Government Configuration Baseline (USGCB) (id='xccdf_org.ssgproject.content_profile_usgcb-rhel6-server')
        3:  Common Profile for General-Purpose Systems (id='xccdf_org.ssgproject.content_profile_common')
        4:  PCI-DSS v3 Control Baseline for Red Hat Enterprise Linux 6 (id='xccdf_org.ssgproject.content_profile_pci-dss')
        5:  Example Server Profile (id='xccdf_org.ssgproject.content_profile_CS2')
        6:  C2S for Red Hat Enterprise Linux 6 (id='xccdf_org.ssgproject.content_profile_C2S')
        7:  Common Profile for General-Purpose SystemsUpstream STIG for RHEL 6 Server (id='xccdf_org.ssgproject.content_profile_stig-rhel6-server-upstream')
        8:  Common Profile for General-Purpose SystemsServer Baseline (id='xccdf_org.ssgproject.content_profile_server')
        9:  Red Hat Corporate Profile for Certified Cloud Providers (RH CCP) (id='xccdf_org.ssgproject.content_profile_rht-ccp')
Choose profile by number (empty for (default) profile): 2
Online remediation (1, y or Y for yes, else no):                                                                   
Schedule:                                                                   
 - not before (YYYY-MM-DD HH:MM in UTC, empty for NOW): 2014-07-30 01:00
 - repeat after (hours or @daily, @weekly, @monthly, empty or 0 for no repeat): @daily
Task created with ID '1'. It is currently set as disabled. You can enable it with `oscapd-cli task 1 enable`.
```
As the command-line interface suggests, we need to enable the task.
```bash
# enable previously created task of given ID
oscapd-cli task 1 enable
```
We may also want to see the HTML guide of our specified task to confirm it will do what we need.
```bash
# get the HTML guide of task of ID 1
oscapd-cli task 1 guide > guide.html
# open the guide in firefox
firefox guide.html
```
At this point `oscapd` will evaluate the local machine at `1:00 AM UTC` every
day and store all the results. To finish this use-case, lets see how we can
query the results after a week of evaluations.
```bash
# list all available results of task 1
$ oscapd-cli result 1
7
6
5
4
3
2
1
# get the verbatim results ARF of the 4th result of task 1
oscapd-cli result 1 4 arf > exported-arf.xml
# get the HTML report of previously mentioned result
oscapd-cli result 1 4 report > report.html
# open the report in firefox
firefox report.html
```

### Solicited evaluation
Sometimes we may want to run the evaluation outside the schedule for testing
or other purposes. The task may even be scheduled to never run automatically!
Such tasks are sometimes necessary.

```bash
# run task of ID 1 immediately
oscapd-cli task 1 run
# query available results
oscapd-cli result 1
8
7
6
# [snip]
# fetch ARF of result 8 of task 1
oscapd-cli result 1 8 arf > exported-arf.xml
```

### Evaluate something else than local machine
Every task has a *target* attribute that can take various forms:
* localhost -- scan the local machine, the same machine the daemon runs on
* ssh://auditor@192.168.0.22 -- scan remote machine of given IP with given username
  * make sure you can log onto the same machine non-interactively!
* ssh+sudo://auditor@192.168.0.22 -- scan remote machine of given IP with given username with sudo privileges
  * sudo mustn't require tty
* vm://qemu+kvm://localhost/VM1 -- virtual machine -- work in progress, subject to change
* docker://container_id -- local container -- work in progress, subject to change

The rest of the use-case is similar to previously mentioned use-cases. It is
important to remark that the *SCAP* content only needs to be available on the
local machine -- the machine that runs *OpenSCAP-daemon*. It is not necessary
to perform any extra manual action to get the content to the scanned machines,
this is done automatically.

### Scan all images in my registry to make sure no vulnerable images are published
When maintaining a registry it makes sense to unpublish images that have known
vulnerabilities to prevent people from using them.

We need to react to the CVE feeds changing and re-scan the images and of course
we need to scan all new images incoming into the registry.

This is a future use-case that hasn't been fully implemented yet.

## Requirements
* [*python2*](http://python.org) >= 2.6 OR [*python3*](http://python.org) >= 3.2
  * full source compatibility with *python2* and *python3*
* [*OpenSCAP*](http://open-scap.org) >= 1.2.6
* [*dbus-python*](http://www.freedesktop.org/wiki/Software/DBusBindings/)
* (optional) [*Atomic*](http://www.projectatomic.io) >= 1.4
* (optional) [*docker*](http://www.docker.com)

## Running the test-suite
The test-suite can be run without installing the software.

```bash
cd openscap-daemon
cd tests
./make_check
```

## Installation on Linux (standalone on host)
```bash
cd openscap-daemon
# as a python2 application
sudo python2 setup.py install
# as a python3 application
sudo python3 setup.py install
```

## Building a container with OpenSCAP Daemon

Containerized version of OpenSCAP Daemon is used as a backend for the
'atomic scan' command. Atomic scan can scan containers and images
for vulnerabilities and configuration compliance.

You can build and install the container image using these commands:

```bash
./generate-dockerfile.py
docker build -t openscap .
atomic install openscap
```

At this point you can run 'atomic scan' on the host.
The image is not meant to be run outside of the atomic command.

The image is based on Fedora and contains OpenSCAP, OpenSCAP Daemon
and SCAP Security Guide as they are available in Fedora packages.
If you need the latest code from upstream git of these components
instead, you can pass `--openscap-from-git`, `--ssg-from-git` and/or
`--daemon-from-git` to the `./generate-dockerfile.py`.


## API Consumers
> Please do not rely on the API just yet, we reserve the right to make breaking
> changes. The API will stabilize in time for 1.0.0 release.

OpenSCAP-daemon provides a stable dbus API that is designed to be used by
other projects.

### Atomic Integration
OpenSCAP-daemon is used to implement the `atomic scan` functionality.
`atomic scan` allows users to scan containers and container images for
vulnerabilities.

### Cockpit Integration
Features:
* declare new tasks, schedule when they run, set how they repeat
* generate HTML guides of scheduled tasks
* show past results of tasks
* get ARFs, HTML reports for past results
* set tasks to automatically push results to external result stores
  * most importantly to [*scaptimony*](http://github.com/OpenSCAP/scaptimony)

### Foreman Integration
Provide a way to reliably do one-off tasks. Unify various `oscap` runners into
one code-base.
