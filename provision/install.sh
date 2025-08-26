#!/bin/bash
set -e

# -----------------------------
# Настройки
# -----------------------------
source /vagrant_provision/config.sh

export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical

PACKAGES=(
    sqlite3
    python3
    python3-venv
    python3-pip
    python3-wheel
    libssl-dev
    libsodium-dev
    git
    curl
    freeradius
    freeradius-utils
    perl
    libconfig-inifiles-perl
    libtry-tiny-perl
    liblwp-protocol-https-perl
    libjson-perl
    libunicode-string-perl
    liburi-perl
    libpq-dev
    libdbd-sqlite3-perl
    liburi-encode-perl
    libdigest-sha-perl
)

# -----------------------------
# Установка пакетов
# -----------------------------
echo "[INFO] Updating package index and installing required packages..."

sudo apt-get update && apt-get upgrade -y
sudo apt-get install -y "${PACKAGES[@]}"

# -----------------------------
# Установка PrivacyIDEA
# -----------------------------
echo "[INFO] Installing PrivacyIDEA..."

sudo mkdir -p /etc/privacyidea /opt/privacyidea /var/log/privacyidea
sudo useradd -r -M -U -d /opt/privacyidea privacyidea
touch /etc/privacyidea/privacyidea.sqlite
sudo chown -R privacyidea:privacyidea /opt/privacyidea /etc/privacyidea /var/log/privacyidea

sudo -su privacyidea bash <<EOSU
export PI_VERSION=${PI_VERSION}
python3 -m venv /opt/privacyidea
source /opt/privacyidea/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r "https://raw.githubusercontent.com/privacyidea/privacyidea/v${PI_VERSION}/requirements.txt"
python3 -m pip install "privacyidea==${PI_VERSION}"
EOSU

sudo tee /etc/privacyidea/pi.cfg > /dev/null <<EOF
import os
import logging

# The realm, where users are allowed to login as administrators
SUPERUSER_REALM = ['super']
# Your database
SQLALCHEMY_DATABASE_URI = "sqlite:////etc/privacyidea/privacyidea.sqlite"
# This is used to encrypt the auth_token
SECRET_KEY = 't0p s3cr3t'
# This is used to encrypt the admin passwords
PI_PEPPER = "Never know..."
# This is used to encrypt the token data and token passwords
PI_ENCFILE = '/etc/privacyidea/enckey'
# This is used to sign the audit log
PI_AUDIT_KEY_PRIVATE = '/etc/privacyidea/private.pem'
PI_AUDIT_KEY_PUBLIC = '/etc/privacyidea/public.pem'
PI_AUDIT_SQL_TRUNCATE = True
# The Class for managing the SQL connection pool
PI_ENGINE_REGISTRY_CLASS = "shared"
PI_AUDIT_POOL_SIZE = 20
PI_LOGFILE = '/var/log/privacyidea/privacyidea.log'
PI_LOGLEVEL = logging.INFO
EOF


sudo chown -R privacyidea:privacyidea /etc/privacyidea/
sudo chmod 640 /etc/privacyidea/pi.cfg

SQLITE3="/usr/bin/sqlite3"

test -x ${SQLITE3} || (echo "Could not find sqlite3!" && exit 1)

DATABASE=/etc/privacyidea/users.sqlite
echo "create table users (id INTEGER PRIMARY KEY ,\
	username TEXT UNIQUE,\
	password TEXT, \
	rpcm_group TEXT);" | ${SQLITE3} ${DATABASE}

cat <<END > /etc/privacyidea/usersdb.install
{'Server': '/',
 'Driver': 'sqlite',
 'Database': '/etc/privacyidea/users.sqlite',
 'Table': 'users',
 'Limit': '500',
 'Editable': '1',
 'Map': '{"userid": "id", "username": "username",  "password": "password", "rpcm_group": "rpcm_group"}',
 'Password_Hash_Type': 'SSHA512'
}
END
sudo chown privacyidea:privacyidea ${DATABASE}

# -----------------------------
# Инициализация PrivacyIDEA
# -----------------------------
echo "[INFO] Running pi-manage tasks..."
sudo -su privacyidea bash <<EOSU
PEPPER="$(tr -dc A-Za-z0-9_ </dev/urandom | head -c24)" && echo "PI_PEPPER = '$PEPPER'" >> /etc/privacyidea/pi.cfg
SECRET="$(tr -dc A-Za-z0-9_ </dev/urandom | head -c24)" && echo "SECRET_KEY = '$SECRET'" >> /etc/privacyidea/pi.cfg
source /opt/privacyidea/bin/activate

export PI_URL=http://localhost:5000/validate/check

pi-manage setup create_enckey
pi-manage setup create_audit_keys
pi-manage createdb
pi-manage db stamp head -d /opt/privacyidea/lib/privacyidea/migrations/
pi-manage config resolver create localusers sqlresolver /etc/privacyidea/usersdb.install
pi-manage config realm create localsql localusers
pi-manage admin add ${PI_ADMIN_USER} -p ${PI_ADMIN_PASS}
EOSU

# -----------------------------
# Настройка FreeRADIUS
# -----------------------------
echo "[INFO] Configuring FreeRADIUS..."
rm /etc/freeradius/3.0/mods-available/perl
touch /etc/freeradius/3.0/mods-available/perl
sudo tee /etc/freeradius/3.0/mods-available/perl > /dev/null <<'EOF'
perl { 
	filename = ${modconfdir}/${.:instance}/privacyidea_radius.pm 
	perl_flags = "-T"
}
EOF
ln -s /etc/freeradius/3.0/mods-available/perl /etc/freeradius/3.0/mods-enabled/

touch /etc/freeradius/3.0/sites-available/privacyidea
sudo tee /etc/freeradius/3.0/sites-available/privacyidea > /dev/null <<'EOF'
server default {
        listen {
                type = auth
                ipaddr = *
                port = 0
                limit {
                        max_connections = 16
                        lifetime = 0
                        idle_timeout = 30
                }
        }

        listen {
                ipaddr = *
                port = 0
                type = acct
                limit {
                }
        }

        authorize {
                preprocess
                digest
                suffix
                ntdomain
                files
                expiration
                logintime
                pap
                update control {
                        Auth-Type := Perl
                }
        }

        authenticate {
                Auth-Type Perl {
                        perl
                }
                digest
        }

        preacct {
                suffix
                files
        }

        accounting {
                detail
        }

        session {
                }
        post-auth {
                }
        pre-proxy {
                }
        post-proxy {
                }
}
EOF
ln -s /etc/freeradius/3.0/sites-available/privacyidea /etc/freeradius/3.0/sites-enabled/
rm /etc/freeradius/3.0/sites-enabled/default

touch /etc/privacyidea/rlm_perl.ini
sudo tee /etc/privacyidea/rlm_perl.ini > /dev/null <<'EOF'
[Default]
URL = http://localhost:5000/validate/check
REALM = localsql
Debug = False
SSL_CHECK = False
EOF

rm /etc/freeradius/3.0/users
touch /etc/freeradius/3.0/users
sudo tee /etc/freeradius/3.0/users > /dev/null <<'EOF'
DEFAULT Auth-Type := perl
EOF

rm /etc/freeradius/3.0/clients.conf
touch /etc/freeradius/3.0/clients.conf
sudo tee /etc/freeradius/3.0/clients.conf > /dev/null <<EOF
client 10.210.1.0/0 {

shortname = local
secret = ${FREERAD_SECRET}

}
EOF

touch /etc/freeradius/3.0/mods-config/perl/privacyidea_radius.pm
sudo tee /etc/freeradius/3.0/mods-config/perl/privacyidea_radius.pm > /dev/null <<'EOF'
#
#    privacyIDEA FreeRADIUS plugin
#    2021-07-23 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               URL encode parameters
#    2020-09-09 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add Packet-Src-IP-Address as fallback for client IP.
#    2020-03-21 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add ADD_EMPTY_PASS to send an empty password to
#               privacyIDEA in case no password is given.
#               Allow config section to have different modules
#               with different config files.
#    2019-03-17 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add password splitting
#    2018-01-12 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Substrings of multivalue user attributes can be added
#               to the RADIUS response.
#    2017-10-16 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add Calling-Station-Id
#    2016-09-30 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add attribute mapping
#    2016-08-13 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add user-agent to be displayed in
#               privacyIDEA Client Applicaton Type
#    2015-10-10 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add privacyIDEA-Serial to the response.
#    2015-10-09 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Improve the reading of the config file.
#    2015-09-25 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add the possibility to read config from
#               /etc/privacyidea/rlm_perl.ini
#    2015-06-10 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add using of Stripped-User-Name and Realm from the
#               RAD_REQUEST
#    2015-04-10 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               fix typo in log
#    2015-02-25 cornelius kölbel <cornelius@privacyidea.org>
#               remove the usage of simplecheck and use /validate/check
#    2014-06-25 Cornelius Kölbel
#               changed the used modules from Config::Files to Config::IniFile
#               to make it easily run on CentOS with EPEL, without CPAN
#
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    Copyright 2002  The FreeRADIUS server project
#    Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#    Copyright 2011  LSE Leading Security Experts GmbH
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de




#
# Based on the Example code for use with rlm_perl
#
#

=head1 NAME

freeradius_perl - Perl module for use with FreeRADIUS rlm_perl, to authenticate against
  LinOTP      http://www.linotp.org
  privacyIDEA http://www.privacyidea.org

=head1 SYNOPSIS

   use with freeradius:

   Configure rlm_perl to work with privacyIDEA:
   in /etc/freeradius/users
    set:
     DEFAULT Auth-type := perl

  in /etc/freeradius/modules/perl
     point
     perl {
         module =
  to this file

  in /etc/freeradius/sites-enabled/<yoursite>
  set
  authenticate{
    perl
    [....]

=head1 DESCRIPTION

This module enables freeradius to authenticate using privacyIDEA or LinOTP.

   TODO:
     * checking of server certificate


=head2 Methods

   * authenticate


=head1 CONFIGURATION

The authentication request with its URL and default LinOTP/privacyIDEA Realm
could be defined in a dedicated configuration file, which is expected to be:

  /opt/privacyIDEA/rlm_perl.ini

This configuration file could contain default definition for URL and REALM like
  [Default]
  URL = http://192.168.56.1:5001/validate/check
  REALM =

But as well could contain "Access-Type" specific configurations, e.g. for the
Access-Type 'scope1', this would look like:

  [Default]
  URL = https://localhost/validate/check
  REALM =
  CLIENTATTRIBUTE = Calling-Station-Id

  [scope1]
  URL = http://192.168.56.1:5001/validate/check
  REALM = mydefault

=head1 AUTHOR

Cornelius Koelbel (cornelius.koelbel@lsexperts.de)
Cornelius Koelbel (conrelius@privacyidea.org)

=head1 COPYRIGHT

Copyright 2013, 2014

This library is free software; you can redistribute it
under the GPLv2.

=head1 SEE ALSO

perl(1).

=cut

use strict;
use LWP 6;
use Config::IniFiles;
use Data::Dump;
use Try::Tiny;
use JSON;
use Time::HiRes qw( gettimeofday tv_interval );
use URI::Encode;
use Encode::Guess;


# use ...
# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG %RAD_PERLCONF);

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;


# constant definition for the remapping of return values
use constant RLM_MODULE_REJECT  =>  0; #  /* immediately reject the request */
use constant RLM_MODULE_FAIL    =>  1; #  /* module failed, don't reply */
use constant RLM_MODULE_OK      =>  2; #  /* the module is OK, continue */
use constant RLM_MODULE_HANDLED =>  3; #  /* the module handled the request, so stop. */
use constant RLM_MODULE_INVALID =>  4; #  /* the module considers the request invalid. */
use constant RLM_MODULE_USERLOCK => 5; #  /* reject the request (user is locked out) */
use constant RLM_MODULE_NOTFOUND => 6; #  /* user not found */
use constant RLM_MODULE_NOOP     => 7; #  /* module succeeded without doing anything */
use constant RLM_MODULE_UPDATED  => 8; #  /* OK (pairs modified) */
use constant RLM_MODULE_NUMCODES => 9; #  /* How many return codes there are */

our $ret_hash = {
    0 => "RLM_MODULE_REJECT",
    1 => "RLM_MODULE_FAIL",
    2 => "RLM_MODULE_OK",
    3 => "RLM_MODULE_HANDLED",
    4 => "RLM_MODULE_INVALID",
    5 => "RLM_MODULE_USERLOCK",
    6 => "RLM_MODULE_NOTFOUND",
    7 => "RLM_MODULE_NOOP",
    8 => "RLM_MODULE_UPDATED",
    9 => "RLM_MODULE_NUMCODES"
};

## constant definition for comparison
use constant false => 0;
use constant true  => 1;

## constant definitions for logging
use constant Debug => 1;
use constant Auth  => 2;
use constant Info  => 3;
use constant Error => 4;
use constant Proxy => 5;
use constant Acct  => 6;
# ADDED 
use DBI;
use DBD::SQLite;
use Digest::SHA qw(sha512);
use MIME::Base64;

# You can configure, which config file to use in the perl module definition:
# perl privacyIDEA-A {
#   filename = /usr/share/privacyidea/freeradius/privacyidea_radius.pm
#   config {
#        configfile = /etc/privacyidea/rlm_perl-A.ini
#        }
# }
our $CONFIG_FILE = $RAD_PERLCONF{'configfile'};
our @CONFIG_FILES = ("/etc/privacyidea/rlm_perl.ini", "/etc/freeradius/rlm_perl.ini", "/opt/privacyIDEA/rlm_perl.ini");


our $Config = {};
our $Mapping = {};
our $cfg_file;

$Config->{FSTAT} = "not found!";
$Config->{URL}     = 'http://privacyidea:5000/validate/check';
$Config->{REALM}   = '';
$Config->{CLIENTATTRIBUTE} = '';
$Config->{RESCONF} = "";
$Config->{Debug}   = "FALSE";
$Config->{SSL_CHECK} = "FALSE";
$Config->{TIMEOUT} = 10;
$Config->{SPLIT_NULL_BYTE} = "FALSE";
$Config->{ADD_EMPTY_PASS} = "FALSE";

if ($CONFIG_FILE) {
    @CONFIG_FILES = ($CONFIG_FILE);
}

foreach my $file (@CONFIG_FILES) {
    if (( -e $file )) {
        $cfg_file = Config::IniFiles->new( -file => $file);
        $CONFIG_FILE = $file;
        $Config->{FSTAT} = "found!";
        $Config->{URL} = $cfg_file->val("Default", "URL");
        $Config->{REALM}   = $cfg_file->val("Default", "REALM");
        $Config->{RESCONF} = $cfg_file->val("Default", "RESCONF");
        $Config->{Debug}   = $cfg_file->val("Default", "DEBUG");
        $Config->{SPLIT_NULL_BYTE} = $cfg_file->val("Default", "SPLIT_NULL_BYTE");
        $Config->{ADD_EMPTY_PASS} = $cfg_file->val("Default", "ADD_EMPTY_PASS");
        $Config->{SSL_CHECK} = $cfg_file->val("Default", "SSL_CHECK");
        $Config->{SSL_CA_PATH} = $cfg_file->val("Default", "SSL_CA_PATH");
        $Config->{TIMEOUT} = $cfg_file->val("Default", "TIMEOUT", 10);
        $Config->{CLIENTATTRIBUTE} = $cfg_file->val("Default", "CLIENTATTRIBUTE");
    }
}

sub add_reply_attibute {

    my $radReply = shift;
    my $newValue = shift;

    if (ref($radReply) eq "ARRAY") {
        # This is an array, there is already a value to this replyAttribute
        #&radiusd::radlog( Info, "Adding $newValue to the Reply Attribute, being an array.\n");
        push @$radReply, $newValue;
    } else {
        # This is an empty replyValue, we add the first value
        #&radiusd::radlog( Info, "Adding $newValue to the Reply Attribute, being a string.\n");
        $radReply = [$newValue];
    }
    return $radReply;
}

sub mapResponse {
    # This function maps the Mapping sections in rlm_perl.ini
    # to RADIUS Attributes.
    my $decoded = shift;
    my %radReply;
    my $topnode;
    if ($cfg_file) {
        foreach my $group ($cfg_file->Groups) {
            &radiusd::radlog( Info, "++++ Parsing group: $group\n");
            foreach my $member ($cfg_file->GroupMembers($group)) {
                &radiusd::radlog(Info, "+++++ Found member '$member'");
                $member =~/(.*)\ (.*)/;
                $topnode = $2;
                if ($group eq "Mapping") {
                    foreach my $key ($cfg_file->Parameters($member)){
                        my $radiusAttribute = $cfg_file->val($member, $key);
                        &radiusd::radlog( Info, "++++++ Map: $topnode : $key -> $radiusAttribute");
                        my $newValue = $decoded->{detail}{$topnode}{$key};
                        $radReply{$radiusAttribute} = add_reply_attibute($radReply{$radiusAttribute}, $newValue);
                    };
                }
                if ($group eq "Attribute") {
                    my $radiusAttribute = $topnode;
                    # opional overwrite radiusAttribute
                    my $ra = $cfg_file->val($member, "radiusAttribute");
                    if ($ra ne "") {
                        $radiusAttribute = $ra;
                    }
                    my $userAttribute = $cfg_file->val($member, "userAttribute");
                    my $regex = $cfg_file->val($member, "regex");
                    my $directory = $cfg_file->val($member, "dir");
                    my $prefix = $cfg_file->val($member, "prefix");
                    my $suffix = $cfg_file->val($member, "suffix");
                    &radiusd::radlog( Info, "++++++ Attribute: IF '$directory'->'$userAttribute' == '$regex' THEN '$radiusAttribute'");
                    my $attributevalue="";
                    if ($directory eq "") {
                        $attributevalue = $decoded->{detail}{$userAttribute};
                        &radiusd::radlog( Info, "++++++ no directory");
                    } else {
                        $attributevalue = $decoded->{detail}{$directory}{$userAttribute};
                        &radiusd::radlog( Info, "++++++ searching in directory $directory");
                    }
                    my @values = ();
                    if (ref($attributevalue) eq "") {
                        &radiusd::radlog(Info, "+++++++ User attribute is a string: $attributevalue");
                        push(@values, $attributevalue);
                    }
                    if (ref($attributevalue) eq "ARRAY") {
                        &radiusd::radlog(Info, "+++++++ User attribute is a list: $attributevalue");
                        @values = @$attributevalue;
                    }
                    foreach my $value (@values) {
                        &radiusd::radlog(Info, "+++++++ trying to match $value");
                        if ($value =~ /$regex/) {
                            my $result = $1;
                            $radReply{$radiusAttribute} = add_reply_attibute($radReply{$radiusAttribute}, "$prefix$result$suffix");
                            &radiusd::radlog(Info, "++++++++ Result: Add RADIUS attribute $radiusAttribute = $prefix$result$suffix");
                        } else {
                            &radiusd::radlog(Info, "++++++++ Result: No match, no RADIUS attribute $radiusAttribute added.");
                        }
                    }
                }
            }
        }

        foreach my $key ($cfg_file->Parameters("Mapping")) {
            my $radiusAttribute = $cfg_file->val("Mapping", $key);
            &radiusd::radlog( Info, "+++ Map: $key -> $radiusAttribute");
            $radReply{$radiusAttribute} = add_reply_attibute($radReply{$radiusAttribute}, $decoded->{detail}{$key});
        }
    }
    return %radReply;
}

# ADDED
# Function to check  user password
sub check_ssha512 {
    my ($password, $stored) = @_;

    $stored =~ s/^\{SSHA512\}//;
    my $decoded = decode_base64($stored);

    my $salt_len = length($decoded) - 64;
    my $hash = substr($decoded, 0, 64);
    my $salt = substr($decoded, 64, $salt_len);

    my $check_hash = sha512($password . $salt);

    return $hash eq $check_hash;
}

# Function to handle authenticate
sub authenticate {

    ## show where the config comes from -
    # in the module init we can't print this out, so it starts here
    &radiusd::radlog( Info, "Config File $CONFIG_FILE ".$Config->{FSTAT} );

    # we inherrit the defaults
    my $URL     = $Config->{URL};
    my $REALM   = $Config->{REALM};
    my $RESCONF = $Config->{RESCONF};
    my $SSL_CA_PATH = $Config->{SSL_CA_PATH};

    my $debug   = false;
    if ( $Config->{Debug} =~ /true/i ) {
        $debug = true;
    }
    &radiusd::radlog( Info, "Debugging config: ". $Config->{Debug});

    my $check_ssl = false;
    if ( $Config->{SSL_CHECK} =~ /true/i ) {
        $check_ssl = true;
    }

    &radiusd::radlog( Info, "Verifying SSL certificate: ". $Config->{SSL_CHECK} );

    my $timeout = $Config->{TIMEOUT};

    &radiusd::radlog( Info, "Default URL $URL " );

    # if there exists an auth-type config may overwrite this
    my $auth_type = $RAD_CONFIG{"Auth-Type"};

    try {
        &radiusd::radlog( Info, "Looking for config for auth-type $auth_type");
        if ( ( $cfg_file->val( $auth_type, "URL") )) {
            $URL = $cfg_file->val( $auth_type, "URL" );
        }
        if ( ( $cfg_file->val( $auth_type, "REALM") )) {
            $REALM = $cfg_file->val( $auth_type, "REALM" );
        }
        if ( ( $cfg_file->val( $auth_type, "RESCONF") )) {
            $RESCONF = $cfg_file->val( $auth_type, "RESCONF" );
        }
    }
    catch {
        &radiusd::radlog( Info, "Warning: $@" );
    };

    if ( $debug == true ) {
        &log_request_attributes;
    }

    my %params = ();

    # put RAD_REQUEST members in the privacyIDEA request
    if ( exists( $RAD_REQUEST{'State'} ) ) {
        my $hexState = $RAD_REQUEST{'State'};
        if ( substr( $hexState, 0, 2 ) eq "0x" ) {
            $hexState = substr( $hexState, 2 );
        }
        $params{'state'} = pack 'H*', $hexState;
    }
    if ( exists( $RAD_REQUEST{'User-Name'} ) ) {
        $params{"user"} = $RAD_REQUEST{'User-Name'};
    }
    if ( exists( $RAD_REQUEST{'Stripped-User-Name'} )) {
        $params{"user"} = $RAD_REQUEST{'Stripped-User-Name'};
    }

    if ( exists( $RAD_REQUEST{'User-Password'} ) ) {
        my $password = $RAD_REQUEST{'User-Password'};
        if ( $Config->{SPLIT_NULL_BYTE} =~ /true/i ) {
            my @p = split(/\0/, $password);
            $password = @p[0];
        }
        # Decode password (from <https://perldoc.perl.org/Encode::Guess#Encode::Guess-%3Eguess($data)>)
        my $decoder = Encode::Guess->guess($password);
        if ( ! ref($decoder) ) {
            radiusd::radlog( Info, "Could not find valid password encoding. Sending password as-is." );
            radiusd::radlog( Debug, $decoder );
        } else {
            &radiusd::radlog( Info, "Password encoding guessed: " . $decoder->name);
            $password = $decoder->decode($password);
        }
	# ADDED
	my ($plain_password, $otp) = $password =~ /(.+)(\d{6})$/;
	# EDITED 
        $params{"pass"} = $otp;
    } elsif ( $Config->{ADD_EMPTY_PASS} =~ /true/i ) {
        $params{"pass"} = "";
    }

    # We need to decode the username as well since it might contain special chars
    if ( exists( $params{"user"} ) ) {
        my $decoder = Encode::Guess->guess($params{"user"});
        if ( ! ref($decoder) ) {
            radiusd::radlog( Info, "Could not find valid username encoding. Sending username as-is." );
            radiusd::radlog( Debug, $decoder );
        } else {
            &radiusd::radlog( Info, "Username encoding guessed: " . $decoder->name);
            $params{"user"} = $decoder->decode($params{"user"});
        }
    }

    # Security enhancement sned Message-Authenticator back
    if ( exists( $RAD_REQUEST{'Message-Authenticator'} )) {
        $RAD_REPLY{'Message-Authenticator'} = $RAD_REQUEST{'Message-Authenticator'};
    }

    # URL encode username and password
    my $uri = URI::Encode->new( { encode_reserved => 0 } );
    $params{"user"} = $uri->encode($params{"user"});
    $params{"pass"} = $uri->encode($params{"pass"});
    if ( exists( $RAD_REQUEST{'NAS-IP-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'NAS-IP-Address'};
        &radiusd::radlog( Info, "Setting client IP to $params{'client'}." );
    } elsif ( exists( $RAD_REQUEST{'Packet-Src-IP-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'Packet-Src-IP-Address'};
        &radiusd::radlog( Info, "Setting client IP to $params{'client'}." );
    }
    if (exists ( $Config->{CLIENTATTRIBUTE} ) ) {
        if ( exists( $RAD_REQUEST{$Config->{CLIENTATTRIBUTE}} ) ) {
            $params{"client"} = $RAD_REQUEST{$Config->{CLIENTATTRIBUTE}};
            &radiusd::radlog( Info, "Setting client IP to $params{'client'}." );
        }
    }
    if ( length($REALM) > 0 ) {
        $params{"realm"} = $REALM;
    } elsif ( length($RAD_REQUEST{'Realm'}) > 0 ) {
        $params{"realm"} = $RAD_REQUEST{'Realm'};
    }
    if ( length($RESCONF) > 0 ) {
        $params{"resConf"} = $RESCONF;
    }

    &radiusd::radlog( Info, "Auth-Type: $auth_type" );
    &radiusd::radlog( Info, "url: $URL" );
    &radiusd::radlog( Info, "user sent to privacyidea: $params{'user'}" );
    &radiusd::radlog( Info, "realm sent to privacyidea: $params{'realm'}" );
    &radiusd::radlog( Info, "resolver sent to privacyidea: $params{'resConf'}" );
    &radiusd::radlog( Info, "client sent to privacyidea: $params{'client'}" );
    &radiusd::radlog( Info, "state sent to privacyidea: $params{'state'}" );
    if ( $debug == true ) {
        &radiusd::radlog( Debug, "urlparam $_ = $params{$_}\n" )
        for ( keys %params );
    }
    else {
        &radiusd::radlog( Info, "urlparam $_ \n" ) for ( keys %params );
    }

    my $ua = LWP::UserAgent->new();
    $ua->env_proxy;
    $ua->timeout($timeout);
    &radiusd::radlog( Info, "Request timeout: $timeout " );
    # Set the user-agent to be fetched in privacyIDEA Client Application Type
    $ua->agent("FreeRADIUS");
    if ($check_ssl == false) {
        try {
            # This is only availble with LWP version 6
            &radiusd::radlog( Info, "Not verifying SSL certificate!" );
            $ua->ssl_opts( verify_hostname => 0, SSL_verify_mode => 0x00 );
        } catch {
            &radiusd::radlog( Error, "ssl_opts only supported with LWP 6. error: $_" );
        }
    } else {
        try {
            &radiusd::radlog( Info, "Verifying SSL certificate!" );
            if ( exists( $Config->{SSL_CA_PATH} ) ) {
                if ( length $SSL_CA_PATH ) {
                    &radiusd::radlog( Info, "SSL_CA_PATH: $SSL_CA_PATH" );
                    $ua->ssl_opts(
                        SSL_ca_path => $SSL_CA_PATH,
                        verify_hostname => 1
                    );
                }
                else {
                    &radiusd::radlog( Info,
                        "Verifying SSL certificate against system wide CAs!" );
                    $ua->ssl_opts( verify_hostname => 1 );
                }
            }
        }
        catch {
            &radiusd::radlog( Error,
                "Something went wrong setting up SSL certificate verification: $_" );
        }
    }

    my $starttime = [gettimeofday];
    my $response = $ua->post( $URL, \%params );
    my $content  = $response->decoded_content();
    my $elapsedtime = tv_interval($starttime);
    &radiusd::radlog( Info, "elapsed time for privacyidea call: $elapsedtime" );
    if ( $debug == true ) {
        &radiusd::radlog( Debug, "Content $content" );
    }
    $RAD_REPLY{'Reply-Message'} = "privacyIDEA server denied access!";
    my $g_return = RLM_MODULE_REJECT;

    if ( !$response->is_success ) {
        # This was NO OK 200 response
        my $status = $response->status_line;
        &radiusd::radlog( Info, "privacyIDEA request failed: $status" );
        $RAD_REPLY{'Reply-Message'} = "privacyIDEA request failed: $status";
        $g_return = RLM_MODULE_FAIL;
    }
    try {
        my $coder = JSON->new->ascii->pretty->allow_nonref;
        my $decoded = $coder->decode($content);
        my $message = $decoded->{detail}{message};
        if ( $decoded->{result}{value} ) {
            &radiusd::radlog( Info, "privacyIDEA access granted for $params{'user'} realm='$params{'realm'}'" );

	        # ADDED
            my $db_file = $ENV{"PI_DB_FILE"} || "/etc/privacyidea/users.sqlite";
            my $dsn = "dbi:SQLite:dbname=$db_file";
            my $dbh;
            &radiusd::radlog( Info, "Connecting to SQLite file: $db_file" );

            try {
                $dbh = DBI->connect(
                    $dsn,
                    "",
                    "",
                    { RaiseError => 1, AutoCommit => 1 }
                );
            } catch {
                &radiusd::radlog( Info, "DB connection failed (SQLite): $_" );
                $g_return = RLM_MODULE_REJECT;
                return $g_return;
            };

	        my $username = $RAD_REQUEST{'User-Name'};
	        my $password_otp = $RAD_REQUEST{'User-Password'};
            my ($password, $otp) = $password_otp =~ /(.+)(\d{6})$/;
            my $sth = $dbh->prepare("SELECT password, rpcm_group FROM users WHERE username = ?");
            $sth->execute($username);
            my ($pass_hash, $rcntec_group) = $sth->fetchrow_array();
	        $sth->finish();
            $dbh->disconnect();

            if (!defined $pass_hash || !check_ssha512($password, $pass_hash)) {
                &radiusd::radlog( Info, "Local password check failed for $username" );
                $RAD_REPLY{'Reply-Message'} = "Wrong password";
                $g_return = RLM_MODULE_REJECT;
            } else {
                $rcntec_group = "default_group" unless defined $rcntec_group;
                $RAD_REPLY{'Reply-Message'} = "privacyIDEA access granted";
                $RAD_REPLY{'RCNTEC-RPCM-Group'} = $rcntec_group;

                # Add the response hash to the Radius Reply
                %RAD_REPLY = ( %RAD_REPLY, mapResponse($decoded) );
                &radiusd::radlog( Info, "privacyIDEA access granted for $username realm='$params{'realm'}', local password OK" );

                $g_return = RLM_MODULE_OK;
            }
        }
        elsif ( $decoded->{result}{status} ) {
            &radiusd::radlog( Info, "privacyIDEA Result status is true!" );
            $RAD_REPLY{'Reply-Message'} = $decoded->{detail}{message};
            if ( $decoded->{detail}{transaction_id} ) {
                ## we are in challenge response mode:
                ## 1. split the response in fail, state and challenge
                ## 2. show the client the challenge and the state
                ## 3. get the response and
                ## 4. submit the response and the state to linotp and
                ## 5. reply ok or reject
                $RAD_REPLY{'State'} = $decoded->{detail}{transaction_id};
                $RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
                # Add the response hash to the Radius Reply
                %RAD_REPLY = ( %RAD_REPLY, mapResponse($decoded));
                $g_return  = RLM_MODULE_HANDLED;
            } else {
                &radiusd::radlog( Info, "privacyIDEA access denied for $params{'user'} realm='$params{'realm'}'" );
                #$RAD_REPLY{'Reply-Message'} = "privacyIDEA access denied";
                $g_return = RLM_MODULE_REJECT;
            }
        }
        elsif ( !$decoded->{result}{status}) {
            # An internal error occurred. We use the original return value RLM_MODULE_FAIL
            &radiusd::radlog( Info, "privacyIDEA Result status is false!" );
            $RAD_REPLY{'Reply-Message'} = $decoded->{result}{error}{message};
            &radiusd::radlog( Info, $decoded->{result}{error}{message});
            my $errorcode = $decoded->{result}{error}{code};
            if ($errorcode == 904) {
                $g_return = RLM_MODULE_NOTFOUND;
            } else {
                $g_return = RLM_MODULE_FAIL;
            }
            &radiusd::radlog( Info, "privacyIDEA failed to handle the request" );
        }
    } catch {
        my $e = shift;
        &radiusd::radlog( Info, "$e");
        &radiusd::radlog( Info, "Can not parse response from privacyIDEA." );
    };

    &radiusd::radlog( Info, "return $ret_hash->{$g_return}" );
    return $g_return;

}

sub log_request_attributes {
    # This shouldn't be done in production environments!
    # This is only meant for debugging!
    for ( keys %RAD_REQUEST ) {
        &radiusd::radlog( Debug, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}" );
    }
}


# Function to handle authorize
sub authorize {

    # For debugging purposes only
    # &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle preacct
sub preacct {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {

    # For debugging purposes only
    #       &log_request_attributes;

    # You can call another subroutine from here
    &test_call;

    return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {

    # For debugging purposes only
    #       &log_request_attributes;

    # Loads some external perl and evaluate it
    my ( $filename, $a, $b, $c, $d ) = @_;
    &radiusd::radlog( 1, "From xlat $filename " );
    &radiusd::radlog( 1, "From xlat $a $b $c $d " );
    local *FH;
    open FH, $filename or die "open '$filename' $!";
    local ($/) = undef;
    my $sub = <FH>;
    close FH;
    my $eval = qq{ sub handler{ $sub;} };
    eval $eval;
    eval { main->handler; };
}

# Function to handle detach
sub detach {

    # For debugging purposes only
    #       &log_request_attributes;

    # Do some logging.
    &radiusd::radlog( 0, "rlm_perl::Detaching. Reloading. Done." );
}

#
# Some functions that can be called from other functions
#

sub test_call {

    # Some code goes here
}

1;
EOF

# -----------------------------
# systemd service
# -----------------------------
sudo cat > /etc/systemd/system/privacyidea.service <<EOF
[Unit]
Description=privacyIDEA Service
After=network.target

[Service]
Type=simple
User=privacyidea
Group=privacyidea
WorkingDirectory=/opt/privacyidea
Environment=PATH=/opt/privacyidea/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/privacyidea/bin/pi-manage run -h ${PI_HOST} -p ${PI_PORT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo chmod 644 /etc/systemd/system/privacyidea.service
sudo systemctl daemon-reload
sudo systemctl enable privacyidea.service
sudo systemctl start privacyidea.service
sudo systemctl restart freeradius.service

echo "[INFO] Installation completed successfully!"
