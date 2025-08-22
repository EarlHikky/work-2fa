#!/bin/bash

VENV_DIR="/opt/privacyidea"
CONFIG_FILE="/etc/privacyidea/pi.cfg"
PI_MANAGE="$VENV_DIR/bin/pi-manage"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Файл $CONFIG_FILE не найден!"
    exit 1
fi

if ! grep -q "SECRET_KEY" "$CONFIG_FILE"; then
    SECRET=$(tr -dc A-Za-z0-9_ </dev/urandom | head -c24)
    echo "SECRET_KEY = '$SECRET'" >> "$CONFIG_FILE"
    echo "[Init] Сгенерирован SECRET_KEY"
fi

if ! grep -q "PI_PEPPER" "$CONFIG_FILE"; then
    PEPPER=$(tr -dc A-Za-z0-9_ </dev/urandom | head -c24)
    echo "PI_PEPPER = '$PEPPER'" >> "$CONFIG_FILE"
    echo "[Init] Сгенерирован PI_PEPPER"
fi

if [ ! -f "/etc/privacyidea/enckey" ]; then
    $PI_MANAGE create_enckey
    echo "[Init] Создан enckey"
fi

if [ ! -f "/etc/privacyidea/private.pem" ]; then
    $PI_MANAGE create_audit_keys
    echo "[Init] Созданы audit_keys"
fi

if [ ! -f "/etc/privacyidea/db_init_done" ]; then
    echo "[Init] База данных не инициализирована. Выполняется createdb..."
    $PI_MANAGE createdb
    echo "[Init] Выполняется миграция..."
    $PI_MANAGE db stamp head -d $VENV_DIR/lib/lib/privacyidea/migrations/
    touch /etc/privacyidea/db_init_done
fi

if ! $PI_MANAGE admin list | grep -q "admin"; then
    echo "[Init] Создаётся администратор admin с паролем admin"
    $PI_MANAGE admin add admin -p admin
fi

echo "[Init] Запуск PrivacyIDEA..."
# TODO
/opt/privacyidea/bin/pi-manage run -h 0.0.0.0

