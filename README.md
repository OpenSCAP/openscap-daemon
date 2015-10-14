# OpenSCAP-daemon
> Continuously evaluate your infrastructure for *SCAP* compliance!
> Avoid copying big SCAP files around, avoid having to type long IDs, avoid
> writing ad-hoc bash scripts to solve your compliance needs!

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
  * **virtual machine** -- `oscap-vm` -- work in progress
  * **container** -- `oscap-docker` -- work in progress
* flexible task definition and planning
  * use any valid *SCAP* content -- for example
    [SCAP Security Guide](http://github.com/OpenSCAP/scap-security-guide),
    [NIST USGCB](http://usgcb.nist.gov/), or even
    [RHSA OVAL](https://www.redhat.com/security/data/oval/)
  * evaluate *daily*, *weekly*, *monthly* or in custom intervals
  * evaluate on demand
* parallel task processing
* results storage -- query ARFs of past results, generate HTML reports, get
  `oscap` stdout/stderr
* command-line interface
* *dbus* *API*
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

### Scan local machine every day at 1:00 AM UTC
OpenSCAP-daemon thinks in terms of tasks. Let us first define the task we want
to perform:
```bash
# interactively create a new task
oscapd-cli task_create -i
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
* vm://qemu+kvm://localhost/VM1 -- virtual machine -- work in progress, subject to change
* docker://container_id -- local container -- work in progress, subject to change

The rest of the use-case is similar to previously mentioned use-cases. It is
important to remark that the *SCAP* content only needs to be available on the
local machine -- the machine that runs *OpenSCAP-daemon*. It is not necessary
to perform any extra manual action to get the content to the scanned machines,
this is done automatically.

## Requirements
* [*python2*](http://python.org) >= 2.6
  * we strive for source compatibility with *python3* but consider that *best-effort*
* [*OpenSCAP*](http://open-scap.org) >= 1.2.6
* [*dbus-python*](http://www.freedesktop.org/wiki/Software/DBusBindings/)
* [*Atomic*](http://www.projectatomic.io) >= 1.4

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
sudo python2 setup.py install
```

## Installation on Linux (super privileged container)
OpenSCAP-daemon can be used as a containerized application.
See the [*atomic directory*](atomic) for more information.

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
