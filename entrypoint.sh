#!/usr/bin/env bash
set -e
rsyslogd -f /sentinel/rsyslog.conf -i /sentinel/rsyslog/pid
fluentd -c /sentinel/fluentd.conf 
