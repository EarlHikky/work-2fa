FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    freeradius freeradius-utils \
    perl libperl-dev libconfig-inifiles-perl libtry-tiny-perl \
    liblwp-protocol-https-perl libjson-perl libunicode-string-perl \
    liburi-perl curl wget vim less build-essential libpq-dev \
    cpanminus \
    && cpanm --force URI::Encode Digest::SHA DBD::Pg \
    && rm -rf /var/lib/apt/lists/* /root/.cpanm

RUN mkdir -p /etc/freeradius/3.0/mods-config/perl \
    && mkdir -p /etc/freeradius/3.0/mods-enabled \
    && mkdir -p /etc/freeradius/3.0/sites-enabled

COPY mods-config/perl/privacyidea_radius.pm /etc/freeradius/3.0/mods-config/perl/
COPY mods-enabled/perl /etc/freeradius/3.0/mods-enabled/
COPY sites-enabled/privacyidea /etc/freeradius/3.0/sites-enabled/
COPY users /etc/freeradius/3.0/
COPY clients.conf /etc/freeradius/3.0/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
    && chown -R freerad:freerad /etc/freeradius/3.0 \
    && rm /etc/freeradius/3.0/sites-enabled/default

# TODO
EXPOSE 1812/udp 1813/udp 1812/tcp 1813/tcp

ENTRYPOINT ["/entrypoint.sh"]