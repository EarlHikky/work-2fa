FROM debian:latest

COPY entrypoint.sh /entrypoint.sh

RUN apt-get update && \
    apt-get install -y \
        freeradius \
        freeradius-utils \
        perl \
        libperl-dev \
        libconfig-inifiles-perl \
        libtry-tiny-perl \
        liblwp-protocol-https-perl \
        libjson-perl \
        libunicode-string-perl \
        liburi-perl \
        netcat-traditional \
        curl \
        wget \
        vim \
        less \
        build-essential \
        libpq-dev \
        cpanminus && \
    cpanm --force \
        URI::Encode \
        Digest::SHA \
        DBD::Pg && \
    apt-get clean && \
    apt-get autoremove -y && \    
    rm -rf /var/lib/apt/lists/* /root/.cpanm && \
    rm -f /etc/freeradius/3.0/sites-enabled/default && \
    mkdir -p /etc/freeradius/3.0/mods-config/perl && \
    mkdir -p /etc/freeradius/3.0/mods-enabled && \
    mkdir -p /etc/freeradius/3.0/sites-enabled && \
    mkdir -p /etc/privacyidea/ && \
    chmod +x /entrypoint.sh && \
    chown -R freerad:freerad /etc/freeradius/3.0

COPY --chown=freerad:freerad mods-config/perl/privacyidea_radius.pm /etc/freeradius/3.0/mods-config/perl/
COPY --chown=freerad:freerad mods-enabled/perl /etc/freeradius/3.0/mods-enabled/
COPY --chown=freerad:freerad sites-enabled/privacyidea /etc/freeradius/3.0/sites-enabled/
COPY --chown=freerad:freerad users /etc/freeradius/3.0/
COPY --chown=freerad:freerad clients.conf /etc/freeradius/3.0/
COPY --chown=freerad:freerad rlm_perl.ini /etc/privacyidea/

USER freerad

ENTRYPOINT ["/entrypoint.sh"]