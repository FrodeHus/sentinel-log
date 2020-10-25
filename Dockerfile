FROM ubuntu:20.04
WORKDIR /sentinel
ADD Gemfile .
RUN apt update && \ 
    apt install -y vim curl sudo ruby-dev build-essential rsyslog && \
    gem install bundler && \
    bundle install && \
    apt remove -y build-essential curl && \
    apt autoremove -y
RUN useradd --create-home --shell /bin/bash sentinel
RUN usermod -a -G adm,syslog sentinel
ADD . .
RUN mkdir /sentinel/rsyslog && chown -R sentinel.sentinel /sentinel
USER sentinel
EXPOSE 5142/tcp
EXPOSE 5142/udp
CMD ["./entrypoint.sh"]
