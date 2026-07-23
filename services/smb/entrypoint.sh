#!/bin/sh
set -e
# Start rsyslog first so it's listening on /dev/log before smbd's full_audit
# VFS module tries to write to it - full_audit only supports syslog as its
# output, and without a syslog daemon those log local7 messages are lost
# with no error, no retry, nothing. (config/rsyslog-full-audit.conf keeps
# rsyslogd running as root - see that file for why: /var/log/samba is
# bind-mounted under the EWS's vboxsf-hardened /opt/honeypot mount, which
# ignores chmod, so a plain permission fix here would silently do nothing.)
rsyslogd
exec smbd --foreground --no-process-group
