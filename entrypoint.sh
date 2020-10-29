#!/usr/bin/env bash
set -e
rm -Rf /sentinel/rsyslog/pid
rsyslogd -f /sentinel/rsyslog.conf -i /sentinel/rsyslog/pid
fluentd -c /sentinel/fluentd.conf 
