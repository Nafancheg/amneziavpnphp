# Amnezia VPN Web Panel

Веб-панель управления VPN-серверами Amnezia с поддержкой нескольких протоколов.

## Возможности

### Серверы и протоколы
- Развёртывание VPN-серверов через SSH
- **Мульти-протокольность:** AmneziaWG (AWG), AmneziaWG2 (AWG2), Xray (VLESS/Reality)
- **Мульти-контейнерность:** несколько контейнеров на одном сервере (AWG + AWG2 + Xray)
- **Подключение существующих серверов** (`attach`) с автообнаружением контейнеров и клиентов
- **Отключение сервера** (`detach`) без удаления данных на сервере
- Импорт из сторонних панелей (wg-easy, 3x-ui)

### Клиенты
- Создание/удаление/отключение/восстановление клиентов для AWG, AWG2 и Xray
- **Сроки действия** и **лимиты трафика** с автоматическим отключением по cron
- QR-коды для мобильных приложений
- Скачивание конфигурации

### Безопасность
- Экранирование всех SSH-команд (`escapeshellarg`)
- Верификация SSH-хостов (`StrictHostKeyChecking=accept-new`, managed known_hosts)
- CSRF-защита для критичных веб-форм
- JWT-аутентификация для REST API
- Поддержка LDAP-авторизации

### Мониторинг
- Сбор метрик серверов (CPU, RAM, диск, сеть) и клиентов (трафик, скорость)
- Статистика рукопожатий (handshake) в реальном времени
- Автоматический daemon `collect_metrics.php` с авторестартом через cron

### Прочее
- Бэкап и восстановление серверов
- Мультиязычный интерфейс (русский, английский, испанский, немецкий, французский, китайский)
- Автоперевод через OpenRouter API

## Требования

- Docker
- Docker Compose

## Установка

```bash
git clone https://github.com/Nafancheg/amneziavpnphp.git
cd amneziavpnphp
cp .env.example .env

# Docker Compose V2 (рекомендуется)
docker compose up -d
docker compose exec web composer install

# Docker Compose V1
docker-compose up -d
docker-compose exec web composer install
```

Панель доступна: http://localhost:8082

Вход по умолчанию: `admin@amnez.ia` / `admin123`

## Конфигурация

Файл `.env`:

```
DB_HOST=db
DB_PORT=3306
DB_DATABASE=amnezia_panel
DB_USERNAME=amnezia
DB_PASSWORD=amnezia123

ADMIN_EMAIL=admin@amnez.ia
ADMIN_PASSWORD=admin123

JWT_SECRET=your-secret-key-change-this
```

## Основные сценарии

### Добавление нового сервера

1. Серверы → Добавить сервер
2. Указать: имя, IP-адрес, SSH-порт, логин, пароль
3. (Опционально) Включить импорт из существующей панели — выбрать тип и загрузить бэкап
4. Нажать «Создать сервер»
5. Дождаться развёртывания

### Подключение существующего сервера (Attach)

Подключить сервер с уже установленными контейнерами Amnezia без переустановки:

```bash
docker compose exec web php bin/attach_existing_server.php
```

Скрипт:
- Обнаруживает работающие контейнеры (`amnezia-awg`, `amnezia-awg2`, `amnezia-xray` и др.)
- Определяет протокол каждого контейнера
- Импортирует существующих клиентов (пиры WG, UUID Xray)
- Сохраняет AWG2-параметры (junkPacketCount, protocolVersion, i1–i5)

### Отключение сервера (Detach)

Убрать сервер из панели, не удаляя контейнеры на VPS:

```bash
docker compose exec web php bin/detach_server.php
```

### Создание клиента

1. Открыть страницу сервера
2. Ввести имя клиента
3. (Опционально) Выбрать срок действия и лимит трафика
4. Нажать «Создать»
5. Скачать конфиг или отсканировать QR-код

### Управление сроками действия

Через UI или API:
```bash
# Установить дату истечения
curl -X POST http://localhost:8082/api/clients/123/set-expiration \
  -H "Authorization: Bearer <token>" \
  -d '{"expires_at": "2026-12-31 23:59:59"}'

# Продлить на 30 дней
curl -X POST http://localhost:8082/api/clients/123/extend \
  -H "Authorization: Bearer <token>" \
  -d '{"days": 30}'

# Клиенты с истекающим сроком (в течение 7 дней)
curl http://localhost:8082/api/clients/expiring?days=7 \
  -H "Authorization: Bearer <token>"
```

### Управление лимитами трафика

```bash
# Установить лимит (10 ГБ)
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": 10737418240}'

# Снять лимит
curl -X POST http://localhost:8082/api/clients/123/set-traffic-limit \
  -H "Authorization: Bearer <token>" \
  -d '{"limit_bytes": null}'

# Клиенты с превышенным лимитом
curl http://localhost:8082/api/clients/overlimit \
  -H "Authorization: Bearer <token>"
```

### Бэкапы

```bash
# Создать бэкап
curl -X POST http://localhost:8082/api/servers/1/backup \
  -H "Authorization: Bearer <token>"

# Список бэкапов
curl http://localhost:8082/api/servers/1/backups \
  -H "Authorization: Bearer <token>"

# Восстановить из бэкапа
curl -X POST http://localhost:8082/api/servers/1/restore \
  -H "Authorization: Bearer <token>" \
  -d '{"backup_id": 123}'
```

### Мониторинг и метрики

Сборщик метрик запускается автоматически при старте контейнера и контролируется cron-задачей каждые 3 минуты:

```bash
# Логи сборщика
docker compose exec web tail -f /var/log/metrics_collector.log

# Ручной перезапуск (авторестарт через 3 мин)
docker compose exec web pkill -f collect_metrics.php
```

### Автоматические проверки (cron)

Каждый час автоматически:
- Отключаются клиенты с истекшим сроком: `check_expired_clients.php`
- Отключаются клиенты с превышенным трафиком: `check_traffic_limits.php`

```bash
docker compose exec web tail -f /var/log/cron.log
```

## Аутентификация API

```bash
# Получить JWT-токен
curl -X POST http://localhost:8082/api/auth/token \
  -d "email=admin@amnez.ia&password=admin123"

# Использовать токен
curl -H "Authorization: Bearer <token>" \
  http://localhost:8082/api/servers
```

## Эндпоинты API

### Аутентификация
```
POST   /api/auth/token              — Получить JWT-токен
POST   /api/tokens                  — Создать постоянный API-токен
GET    /api/tokens                  — Список API-токенов
DELETE /api/tokens/{id}             — Отозвать токен
```

### Серверы
```
GET    /api/servers                 — Список серверов
POST   /api/servers/create          — Создать сервер
DELETE /api/servers/{id}/delete     — Удалить сервер
GET    /api/servers/{id}/clients    — Клиенты сервера
```

### Клиенты
```
GET    /api/clients                 — Список клиентов
GET    /api/clients/{id}/details    — Детали клиента (статистика, конфиг, QR)
GET    /api/clients/{id}/qr         — QR-код клиента
POST   /api/clients/create          — Создать клиента
POST   /api/clients/{id}/revoke     — Отключить клиента
POST   /api/clients/{id}/restore    — Восстановить клиента
DELETE /api/clients/{id}/delete     — Удалить клиента
POST   /api/clients/{id}/set-expiration  — Установить срок действия
POST   /api/clients/{id}/extend     — Продлить срок действия
GET    /api/clients/expiring        — Клиенты с истекающим сроком
POST   /api/clients/{id}/set-traffic-limit — Установить лимит трафика
GET    /api/clients/{id}/traffic-limit-status — Статус лимита трафика
GET    /api/clients/overlimit       — Клиенты с превышением лимита
```

### Бэкапы
```
POST   /api/servers/{id}/backup     — Создать бэкап
GET    /api/servers/{id}/backups    — Список бэкапов
POST   /api/servers/{id}/restore    — Восстановить из бэкапа
DELETE /api/backups/{id}            — Удалить бэкап
```

### Импорт
```
POST   /api/servers/{id}/import     — Импорт из сторонней панели
GET    /api/servers/{id}/imports    — История импортов
```

## CLI-утилиты

```
bin/attach_existing_server.php   — Подключение существующего сервера
bin/detach_server.php            — Отключение сервера от панели
bin/list_servers.php             — Список серверов в БД
bin/diagnose_protocol_source.php — Диагностика определения протоколов
bin/collect_metrics.php          — Daemon сбора метрик
bin/check_expired_clients.php    — Проверка истекших клиентов
bin/check_traffic_limits.php     — Проверка лимитов трафика
bin/translate_all.php            — Автоперевод интерфейса
bin/sync_ldap_users.php          — Синхронизация LDAP-пользователей
```

## Структура проекта

```
public/index.php       — Роутинг
inc/                   — Ядро
  Auth.php             — Аутентификация
  DB.php               — Подключение к БД
  Router.php           — URL-маршрутизация
  View.php             — Шаблоны Twig
  VpnServer.php        — Управление серверами
  VpnClient.php        — Управление клиентами
  ServerMonitoring.php — Мониторинг и метрики
  Translator.php       — Многоязычность
  JWT.php              — JWT-авторизация
  QrUtil.php           — Генерация QR-кодов
  PanelImporter.php    — Импорт из wg-easy/3x-ui
  LdapSync.php         — LDAP-интеграция
bin/                   — CLI-скрипты
templates/             — Шаблоны Twig
migrations/            — SQL-миграции
docs/                  — Документация (контракты данных)
storage/               — SSH known_hosts, кэш
```

## Стек технологий

- PHP 8.2
- MySQL 8.0
- Twig 3
- Tailwind CSS
- Docker

## Лицензия

MIT

## Поддержать проект

Если проект оказался полезен, можно поддержать разработку через Tribute: https://t.me/tribute/app?startapp=dzX1
