#!/bin/sh
set -eu

mkdir -p /shared
touch /shared/auth.log

rsyslogd

exec /usr/sbin/sshd -D
