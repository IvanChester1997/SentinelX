#!/bin/sh
set -eu

touch /var/log/auth.log

rsyslogd

exec /usr/sbin/sshd -D
