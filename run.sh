#!/bin/bash

source ./config.sh

sudo -su privacyidea bash <<EOSU
export PI_DB_USER=${POSTGRES_USER}
export PI_DB_PASS=${POSTGRES_PASSWORD}
export PI_DB_NAME=${POSTGRES_DB}
export PI_DB_HOST=${POSTGRES_HOST}
export PI_DB_PORT=${POSTGRES_PORT}

source /opt/privacyidea/bin/activate

pi-manage run -h 0.0.0.0
EOSU