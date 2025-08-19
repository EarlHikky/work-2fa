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
COPY --chown=privacyidea:privacyidea rlm_perl.ini /etc/privacyidea/

RUN chmod +x /entrypoint.sh \
    && chown -R freerad:freerad /etc/freeradius/3.0 \
    && rm /etc/freeradius/3.0/sites-enabled/default

ENTRYPOINT ["/entrypoint.sh"]