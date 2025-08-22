**Стек:**  
- Ubuntu 24.04.3  
- FreeRADIUS 3.2.5,  [GPL-2.0 license](https://github.com/FreeRADIUS/freeradius-server#GPL-2.0-1-ov-file)
- privacyIDEA 3.11.4, [AGPL-3.0 license](https://github.com/privacyidea/privacyidea#AGPL-3.0-1-ov-file)
- PostgreSQL 17.6
- Perl 5.38.2
- Python 3.12.3
- Flask 3.0.3
- Werkzeug 3.0.6


---

## 1. Введение

Решение предоставляет **безопасную и масштабируемую платформу аутентификации** для предприятий.  
Оно объединяет **FreeRADIUS** с **privacyIDEA**, обеспечивая современную многофакторную аутентификацию (MFA).  
Система основана на **открытых технологиях (Open Source)**, что гарантирует гибкость и снижение затрат.  

---

## 2. Архитектура

Схема работы:
1. Пользователь отправляет запрос на аутентификацию
2. FreeRADIUS пересылает запрос в privacyIDEA  
3. privacyIDEA проверяет логин/пароль и второй фактор  
4. PostgreSQL хранит токены, настройки  и пользователей
5. Доступ разрешён или отклонён  

---

## 3. Установка

### 3.1 Установка через Docker Compose

```sh
git clone https://github.com/EarlHikky/work-2fa.git . &&
docker compose up -d --build
```

### 3.2 Ручная установка (Ubuntu 22.04)

#### 1. Установка PostgreSQL

```bash
apt update && apt install -y postgresql
```

Создание пользователя, базы данных, таблицы пользователей:
Подключаемся к Postgres:

```sh
sudo -i -u postgres psql
```

Создаём БД:

```sql
CREATE USER pi_user WITH PASSWORD 'test123';
CREATE DATABASE pi_db OWNER pi_user;
GRANT ALL PRIVILEGES ON DATABASE pi_db TO pi_user;
```

Подключаемся к БД:

```postgressql
\c pi_db
```


Создаём таблицу:
```sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    rpcm_group VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 2. Установка privacyIDEA

Создаем каталоги, под нужды сервиса:

```sh
mkdir /etc/privacyidea /opt/privacyidea /var/log/privacyidea
```

Добавляем системного пользователя:

```sh
useradd -r -M -U -d /opt/privacyidea privacyidea
```

Меняем владельца на ранее созданных каталогах:

```sh
chown privacyidea:privacyidea /opt/privacyidea /etc/privacyidea /var/log/privacyidea
```

Ставим зависимости для работы с пакетами и сборкой:

```sh
apt-get install -y \
    python3 python3-venv python3-distutils python3-pip python3-wheel \
    libssl-dev libldap2-dev libsodium-dev \
    swig \
    git \
    curl \
    gcc
```

Последующие действия будем выполнять из под системного пользователя - `privacyidea`, поэтому переключаемся на него.

```sh
su - privacyidea
```

В документации по инсталяции рекомендуется установка пакетов в виртуальное окружение. Создаем окружение и переключаемся в него:

```sh
python3 -m venv /opt/privacyidea
. /opt/privacyidea/bin/activate
```

Устанавливаем. В переменные окружения добавил переменную с версией приложения.

```sh
export PI_VERSION=3.8.1
```

Через `pip` устанавливаем зависимости самого приложения:

```sh
pip install -r https://raw.githubusercontent.com/privacyidea/privacyidea/v${PI_VERSION}/requirements.txt psycopg2-binary
```

Ставим сам сервис:

```sh
pip install privacyidea==${PI_VERSION}
```

Если установка прошла успешно, создаем новый конфигурационный файл для сервиса:

```sh
vi /etc/privacyidea/pi.cfg
```

Сам файл конфигурации, из основных настроек, нам нужно поменять строку подключения к базе:

```python
import os
import logging
# The realm, where users are allowed to login as administrators
SUPERUSER_REALM = ['super']
# Your database
SQLALCHEMY_DATABASE_URI = (
    f"postgresql+psycopg2://{os.environ.get('PI_DB_USER')}:{os.environ.get('PI_DB_PASS')}"
    f"@{os.environ.get('PI_DB_HOST')}/{os.environ.get('PI_DB_NAME')}"
)
# This is used to encrypt the auth_token
#SECRET_KEY = 't0p s3cr3t'
# This is used to encrypt the admin passwords
#PI_PEPPER = "Never know..."
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

```

Сервис использует механизм шифрования внутренних админских паролей, что бы это работало нужно в значение переменной `PI_PEPPER` (в конфиге `/etc/privacyidea/pi.cfg`), поместить набор рандомных символов:

```sh
PEPPER="$(tr -dc A-Za-z0-9_ </dev/urandom | head -c24)" && echo "PI_PEPPER = '$PEPPER'" >> /etc/privacyidea/pi.cfg
```

Аналогично прописываем значение для переменной - `SECRET_KEY`, значением этого параметра будут зашифровываться наши токены:

```sh
SECRET="$(tr -dc A-Za-z0-9_ </dev/urandom | head -c24)" && echo "SECRET_KEY = '$SECRET'" >> /etc/privacyidea/pi.cfg
```

Теперь при помощи утилиты `pi-manage`,  генерируем ключи и мигрируем схемы в базу:

Генерируем ключ шифрования для бд:

```sh
pi-manage create_enckey
```

Генерируем ключ для верификации лог-записей:

```sh
pi-manage create_audit_keys
```

Экспортируем переменные среды:

```sh
export PI_DB_USER=pi_user
export PI_DB_PASS=test123
export PI_DB_HOST=localhost
export PI_DB_PORT=5432
export PI_DB_NAME=pi_db
export PI_URL=http://localhost:5000/validate/check
```

Создаем структуру для базы:

```sh
pi-manage createdb
pi-manage db stamp head -d /opt/privacyidea/lib/privacyidea/migrations/
```

Добавляем локального админа, для доступа к WebUI админки:

```sh
pi-manage admin add admin
```

Запуск сервера:
```sh
pi-manage runserver
```

> [!warning] Для запуска в прод среде рекомендуется настройка сервера (apache/nginx)

##### TODO 
#### 3. Установка FreeRADIUS

```sh
apt-get install -y \
	freeradius freeradius-utils \
	build-essential \
	perl cpanminus \
	libperl-dev \
	libconfig-inifiles-perl \
	libtry-tiny-perl \
	liblwp-protocol-https-perl \
	libjson-perl \
	libunicode-string-perl \
	liburi-perl \
	libpq-dev 
```

##### Установка модулей Perl:

```sh
cpanm --force URI::Encode Digest::SHA DBD::Pg
```

Редактирование конфигов:

```sh
vim /etc/freeradius/3.0/mods-config/perl/privacyidea_radius.pm
```

```sh
rm /etc/freeradius/3.0/mods-available/perl 
vim /etc/freeradius/3.0/mods-available/perl 
```

```sh
ln -s /etc/freeradius/3.0/mods-available/perl /etc/freeradius/3.0/mods-enabled/
```

```config
perl { 
	filename = ${modconfdir}/${.:instance}/privacyidea_radius.pm 
	perl_flags = "-T"
}
```

Теперь нужно создать конфигурацию для radius-сайта:

```sh
vi /etc/freeradius/3.0/sites-available/privacyidea
```

```config
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
```

Подключаем сайт:

```sh
ln -s /etc/freeradius/3.0/sites-available/privacyidea /etc/freeradius/3.0/sites-enabled/
```

Отключаем дефолтные:
```sh
rm /etc/freeradius/3.0/sites-enabled/default
```

Модуль будет обращаться на REST API основного сервиса, для этого нам нужно создать конфиг для модуля:

```sh
vi /etc/privacyidea/rlm_perl.ini
```

```config
[Default]
URL = http://localhost:5000/validate/check
REALM = postgres_sql
Debug = False
SSL_CHECK = False
```

Указываем способ авторизации, который прописывается в файле - `users`:
```sh
rm /etc/freeradius/3.0/users
vi /etc/freeradius/3.0/users
```

```config
DEFAULT Auth-Type := perl
```

Добавляем клиентов:
```sh
rm /etc/freeradius/3.0/clients.conf
vi /etc/freeradius/3.0/clients.conf
```

```config
client 10.210.1.0/0 {

shortname = local
secret = 'testing123'

}
```

---

## 4. Использование

Добавляем sqlresolver:
![[Pasted image 20250821112907.png]]

Пример конфигурации:
![[Pasted image 20250821124649.png]]

Добавляем область:

![[Pasted image 20250821124726.png]]

Создаём пользователя:
![[Pasted image 20250821124927.png]]

Создаём токен для пользователя:

![[Pasted image 20250821125042.png]]


![[Pasted image 20250821125112.png]]

Добавляем RADIUS-сервер на RPCM:

![[Pasted image 20250821125151.png]]

---

