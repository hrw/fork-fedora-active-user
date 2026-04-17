fedora-active-user
==================

[![Build Status](https://travis-ci.org/pypingou/fedora-active-user.svg?branch=master)](https://travis-ci.org/pypingou/fedora-active-user)

This script generates a small report of the recent activity
of a fellow Fedora contributor using either their FAS (Fedora
Account System) login (recommended) or their email address.

The script checks:

- last builds on koji
- last update on Bodhi
- last update on Bugzilla (takes a while)
- last email set to mailing lists
- last actions recorded by fedmsg

All Fedora mailing lists hosted on
[lists.fedoraproject.org](lists.fedoraproject.org)
system are checked.


Dependencies
------------
This script depends on the `python3-urllib-gssapi` package.

To get data from FAS you need active Kerberos ticket:

```
$ kinit YOUR_USERID@FEDORAPROJECT.ORG

```

