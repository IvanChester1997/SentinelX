FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log \
    && useradd -m -s /bin/bash labuser \
    && echo 'labuser:LabPassword123!' | chpasswd \
    && printf '%s\n' \
        'PermitRootLogin no' \
        'PasswordAuthentication yes' \
        'SyslogFacility AUTHPRIV' \
        'LogLevel INFO' \
        >> /etc/ssh/sshd_config

COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
