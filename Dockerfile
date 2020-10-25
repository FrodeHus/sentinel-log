FROM ubuntu:20.04
RUN apt update && \ 
    apt install -y curl sudo ruby-dev build-essential rsyslog && \
    curl -L https://toolbelt.treasuredata.com/sh/install-ubuntu-focal-td-agent4.sh | sh && \
    td-agent-gem install fluent-plugin-azure-loganalytics && \
    gem install fluent-plugin-filter-geoip && \
    apt remove -y build-essential curl && \
    apt autoremove -y
ADD rsyslog.conf /etc/rsyslog.conf
WORKDIR /sentinel
ADD fluentd.conf .
