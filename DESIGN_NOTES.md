# Design Notes

## Puzzle Pieces

###  Task
  * target
    * host
    * VM $URL
    * container / image $ID
  * input content
  * tailoring
  * profile id, datastream id, ...
  * HTML guide can be always generated

### Task Result
 * ARF always
 * HTML report can be always generated


## CLI use-cases
```
$ oscapd-cli task list

Active tasks:

ID  | Title                   | Next run                      | Repeats |
-------------------------------------------------------------------------
2   | Weekly USGCB evaluation | 2015-04-10 01:00 (in 8 hours) | @weekly |
3   | Daily STIG evaluation   | 2015-03-09 23:00 (in 6 hours) | @daily  |
4   | One-off evaluation      | 2015-03-09 23:30 (in 6 hours) | -       |

Inactive tasks:

ID  | Title
------------------------------------------------------------------------
1   | Testing evaluation
```

```
$ oscapd-cli task 2

ID:          2
Title:       Weekly USGCB evaluation

Target:      localhost
Input file:  /usr/share/xml/scap/ssg/content/ssg-rhel6-ds.xml
Tailoring:   N/A
Profile ID:  xccdf_org.ssgproject.content_profile_usgcb-rhel6-server

Next run:    2015-04-10 01:00 (in 8 hours)
Repeats:     @weekly = 168 hours
Time slip:   no_slip

ARF upload:  disabled
One-off:     false

Results:

ID  | Timestamp
----------------------
23  | 2015-04-03 01:13
14  | 2015-03-27 01:11
11  | 2015-03-20 01:15
````

```
$ oscapd-cli result 23

ID:         23
Task ID:    2
Timestamp:  2015-04-03
ARF path:   /var/lib/oscapd-cli/results/23/results-arf.xml
```

```
$ oscapd-cli result 23 report > report.html
```
```
$ oscapd-cli result 23 arf > arf.xml
```
```
# generate report of last result from task 2
$ oscapd-cli result 2/last report
```
```
$ oscapd-cli task 2 disable
$ oscapd-cli task 2 enable
```

```
# manually update oscapd-cli, for debugging purposes
$ oscapd-cli update

Found 4 tasks in total, 3 enabled tasks.
````
