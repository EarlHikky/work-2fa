FROM ubuntu:22.04

COPY entrypoint.sh /entrypoint.sh

RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-distutils \
    python3-pip \
    python3-wheel \
    libssl-dev \
    libldap2-dev \
    libsodium-dev \
    swig \
    git \
    curl \
    vim \
    gcc && \
    apt-get clean && \
    apt-get purge -y gcc git && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -M -U -d /opt/privacyidea privacyidea && \
    mkdir -p /etc/privacyidea /opt/privacyidea /var/log/privacyidea && \
    chown -R privacyidea:privacyidea /opt/privacyidea /etc/privacyidea /var/log/privacyidea && \
    chmod +x /entrypoint.sh
    
USER privacyidea
WORKDIR /opt/privacyidea

ENV PI_VERSION=3.8.1

RUN python3 -m venv /opt/privacyidea && \
    /opt/privacyidea/bin/pip install --no-cache-dir \
        -r https://raw.githubusercontent.com/privacyidea/privacyidea/v${PI_VERSION}/requirements.txt && \
    /opt/privacyidea/bin/pip install --no-cache-dir privacyidea==${PI_VERSION} \
    psycopg2-binary && \
    chown -R privacyidea:privacyidea /opt/privacyidea /etc/privacyidea /var/log/privacyidea

COPY --chown=privacyidea:privacyidea pi.cfg /etc/privacyidea/

ENTRYPOINT ["/entrypoint.sh"]