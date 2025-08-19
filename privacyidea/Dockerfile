FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 python3-venv python3-distutils python3-pip python3-wheel git vim\
    libssl-dev swig libldap2-dev libsodium-dev gcc \
    && rm -rf /var/lib/apt/lists/* 

RUN mkdir -p /etc/privacyidea /opt/privacyidea /var/log/privacyidea \
    && useradd -r -M -U -d /opt/privacyidea privacyidea \
    && chown -R privacyidea:privacyidea /opt/privacyidea /etc/privacyidea /var/log/privacyidea

USER privacyidea
WORKDIR /opt/privacyidea

ENV PI_VERSION=3.8.1

RUN python3 -m venv /opt/privacyidea \
    && /opt/privacyidea/bin/pip install --no-cache-dir \
        -r https://raw.githubusercontent.com/privacyidea/privacyidea/v${PI_VERSION}/requirements.txt \
    && /opt/privacyidea/bin/pip install --no-cache-dir privacyidea==${PI_VERSION} \
    psycopg2-binary

COPY --chown=privacyidea:privacyidea pi.cfg /etc/privacyidea/

USER root
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]