# CHIMERA

**Адаптивный транспорт против цензуры.** CHIMERA совмещает stealth-идею Reality
(прозрачный fallback, Chrome-like ClientHello) с устойчивостью к потерям и
адаптивным выбором transport/endpoints.

| | Stealth (пробинг + отпечаток) | Устойчивость к потерям | Адаптация |
|---|:---:|:---:|:---:|
| **VLESS-Reality** | глубокий, но TCP-only | умирает на троттлинге | нет |
| **Hysteria 2** | палится по QUIC-отпечатку | rate-based CC | нет |
| **CHIMERA** | Reality-класс на TCP, uTLS Chrome по тегу | QUIC/ElasticCC по тегу | auto QUIC/TCP, failover, telemetry |

Один Go-бинарь на данные (`CGO_ENABLED=0`, без внешних зависимостей на
клиенте) плюс отдельный сервис для выдачи ключей доступа и списка серверов.

**Содержание:** [Архитектура](#архитектура) · [Сборка](#сборка) ·
[Запуск VPN-сервера и клиента](#запуск-vpn-сервера-и-клиента) ·
[Control-plane: ключи доступа и каталог серверов](#control-plane-ключи-доступа-и-каталог-серверов) ·
[Приложение (Windows tray)](#приложение-windows-tray) ·
[Ограничения текущей версии](#ограничения-текущей-версии) · [Структура](#структура)

---

## Архитектура

Система состоит из трёх независимо разворачиваемых частей:

1. **Data-plane сервер** (`cmd/chimera server`) — то, через что реально идёт
   зашифрованный/замаскированный трафик пользователя. Может работать в двух
   режимах авторизации:
   - `-auth-mode useracl` — старый режим "по списку": фиксированный список
     short-ID на сервере (флаг `-sid`, YAML-файл `-users-file` для
     динамического управления без рестарта). Годится для одиночного
     BYO-сервера без общего аккаунта.
   - `-auth-mode controlplane` — новый режим: сервер не хранит список
     разрешённых клиентов сам, а на лету проверяет подписанный
     control-plane'ом capability-токен, который предъявляет клиент.
2. **Control-plane** (`cmd/chimera-control` + `cmd/chimera-control-cli`) —
   отдельный сервис, который выдаёт ключи доступа (account-number),
   превращает их в короткоживущие подписанные токены и раздаёт куррированный
   список серверов (`GET /v1/catalog`). Он не проксирует пользовательский
   трафик вообще — только выдаёт токены и метаданные. См.
   [раздел ниже](#control-plane-ключи-доступа-и-каталог-серверов).
3. **Клиент** — либо чистый CLI (`cmd/chimera proxy`/`tun`/`connect`), либо
   Flutter-приложение для Windows (`app/`) с треем и графическим интерфейсом.

Данные и управление ключами физически разделены: `chimera-control` может
жить на отдельном хосте от любого VPN-сервера, а VPN-серверов может быть
сколько угодно — все они независимо проверяют один и тот же токен по
публичному Ed25519-ключу control-plane, без обращения к общей базе на
каждое соединение (см. ниже про статeless-токены).

## Сборка

```bash
./scripts/build.sh     # Linux/macOS → bin/chimera (CLI, data-plane + клиент)
```
```powershell
.\scripts\build-app-windows.ps1     # Windows → dist\chimera_setup.exe (установщик приложения)
```

`build.sh` собирает CLI-бинарь со всеми фичами сразу (Chrome-отпечаток TLS,
QUIC-транспорт, полный TUN-туннель). `build-app-windows.ps1` собирает
графическое Windows-приложение целиком, вплоть до готового установщика
(детали — в разделе [«Приложение»](#приложение-windows-tray) ниже); чистый
CLI под Windows, `bin\chimera.exe`, при необходимости собирается тем же
`build.ps1`.

Control-plane собирается обычным `go build` — CGO не нужен (SQLite —
чистый Go, `modernc.org/sqlite`):

```bash
go build -o chimera-control     ./cmd/chimera-control
go build -o chimera-control-cli ./cmd/chimera-control-cli
```

## Запуск VPN-сервера и клиента

### Режим useracl (без control-plane, для одного BYO-сервера)

```bash
# 1. Ключи + shortID
./bin/chimera keygen
SID=0a1b2c3d

# 2. Сервер
./bin/chimera server -listen :443 -steal-host www.microsoft.com:443 -priv <PRIV> -sid $SID

# 3. Локальный SOCKS5 на клиенте
./bin/chimera proxy -server <IP1>:443,<IP2>:443 -pbk <PUB> -sni www.microsoft.com -sid $SID

# 4. Трафик через туннель
curl --socks5-hostname 127.0.0.1:1080 https://example.org/

# Share link + terminal QR
./bin/chimera link -host <SERVER_IP> -port 443 -pbk <PUB> -sid $SID -sni www.microsoft.com -tag MyServer -qr
```

### Режим controlplane (сервер входит в общий каталог с account-ключами)

```bash
./bin/chimera server -listen :443 -steal-host www.microsoft.com:443 -priv <PRIV> \
    -auth-mode controlplane \
    -controlplane-pubkey <HEX_ПУБЛИЧНОГО_КЛЮЧА_CONTROL_PLANE> \
    -controlplane-addr http://control.example.com:8443

./bin/chimera proxy -server <IP>:443 -pbk <PUB> -sni www.microsoft.com \
    -sid <SHORT_ID_УСТРОЙСТВА_ИЗ_REDEEM> -token <ТОКЕН_ИЗ_REDEEM> -listen 127.0.0.1:1080
```

**Важно:** в режиме `controlplane` значение `-sid` — это не произвольная
метка сервера, а **short ID конкретного устройства**, выданный
control-plane'ом при `POST /v1/session/redeem` (поле `short_id_hex` в
ответе). Сервер сверяет short ID, восстановленный из криптографического
ClientHello клиента, с тем, что зашит в предъявленном токене — если они не
совпадают, соединение молча закрывается (выглядит как обычный TLS-визит на
steal-host для стороннего наблюдателя, но данные не идут). Флутер-приложение
делает это сопоставление автоматически (`AccountInfo.shortIdHex`,
`main.dart`'s `_effectiveSid`) — руками эту связку нужно повторять только
при ручной работе через голый CLI.

На Windows используйте `bin\chimera.exe` после `.\scripts\build.ps1` — эта
сборка уже включает full-tunnel режим, отдельно ничего досоставлять не нужно:

```powershell
bin\chimera.exe tun -server <IP>:443 -pbk <PUB> -transport auto -setup-dry-run
bin\chimera.exe tun -server <IP>:443 -pbk <PUB> -transport auto -setup-elevate -setup-os -setup-firewall
bin\chimera.exe tun -dev chimera -setup-restore
```

`-setup-dry-run` печатает план настройки сети без создания TUN-интерфейса.
`-setup-os` настраивает маршруты/DNS и требует прав администратора —
`-setup-elevate` сам перезапускает команду через UAC prompt. `-setup-firewall`
добавляет правила, блокирующие утечку DNS мимо туннеля. `-setup-killswitch`
дополнительно блокирует вообще весь исходящий трафик, кроме туннеля, loopback
и самого сервера. `-setup-restore` откатывает все сетевые изменения вручную,
если что-то пошло не так.

> **Сервер и клиент обязаны быть собраны из одной и той же версии** — при
> рассинхроне поддерживаемых транспортов CLI явно скажет, какой флаг пересобрать.
>
> QUIC-транспорт пока не поддерживает `-auth-mode controlplane` (только
> `useracl`) — сервер откажется стартовать с понятной ошибкой, если попросить
> обратное; используйте TCP-Reality (транспорт по умолчанию) для
> controlplane-серверов.

## Control-plane: ключи доступа и каталог серверов

`chimera-control` — единственный процесс, у которого есть доступ к базе
данных (SQLite). Он отвечает на два вопроса: «валиден ли этот ключ доступа?»
и «какие сервера сейчас в каталоге?». Сам трафик пользователей через него не
идёт.

### Развёртывание

```bash
# 1. Генерируем подписывающий ключ (Ed25519) -- держите control.key в секрете,
#    control.key.pub можно свободно раздавать.
./chimera-control keygen -out control.key

# 2. Запускаем сервис. Публичный API слушает снаружи (redeem/refresh/catalog),
#    admin API -- только на loopback (управление через chimera-control-cli).
./chimera-control serve \
    -db control.db \
    -signing-key control.key \
    -listen :8443 \
    -admin-listen 127.0.0.1:8444 \
    -admin-token "$(openssl rand -hex 32)"
```

В проде запускайте под systemd отдельным непривилегированным пользователем,
с БД и ключом в директории, недоступной для чтения посторонним (`chmod 600`).
Публичный порт (`8443`) можно и нужно спрятать за TLS-терминацией
(nginx/Caddy + домен), если инстанс смотрит в интернет напрямую — сам
`chimera-control` TLS не поднимает.

### Выдача ключа доступа (account-number)

Самообслуживания/биллинга нет — ключи выдаёт оператор вручную:

```bash
export CHIMERA_CONTROL_ADMIN_TOKEN=...   # или -admin-token на каждый вызов
chimera-control-cli account create -expires 2027-01-01T00:00:00Z -device-limit 5
# account number (shown once, store it now): XXXX-XXXX-XXXX-XXXX
```

Формат ключа — Crockford base32 без `0/O/1/I`, 16 символов, `XXXX-XXXX-XXXX-XXXX`
(~78 бит энтропии). Ключ печатается **один раз** и нигде не хранится — в
базе остаётся только `sha256(ключ)`, так что даже компрометация БД не
раскрывает выданные ключи задним числом.

Ключ можно отозвать (`account revoke -number ...`), а конкретное
устройство — мгновенно заблокировать по его short ID
(`revoke -sid <hex>`), не дожидаясь истечения текущего токена.

### Как это проверяется на клиенте (redeem/refresh)

Ключ сам по себе никогда не уходит на VPN-сервер — клиент обменивает его на
подписанный capability-токен через control-plane:

```
POST /v1/session/redeem {"account_number": "...", "device_pubkey": "..."}
  → {"token": "...", "short_id_hex": "..."}
```

Control-plane проверяет `sha256(ключ)` в своей БД (существует ли аккаунт,
активен ли, не истёк ли срок) и подписывает Ed25519-токен на ~24 часа с TTL.
Раз в сутки клиент фоново продлевает его через `POST /v1/session/refresh` —
повторно вводить ключ для этого не нужно.

Дальше VPN-сервер проверяет этот токен **локально, без сети и без похода в
БД** — просто проверкой Ed25519-подписи и `expires_at` внутри самого токена
(`internal/controlplane.Verifier.Verify`). Поэтому проверка на каждое новое
соединение быстрая и не создаёт нагрузку на control-plane, а временная
недоступность control-plane не рвёт уже установленные соединения.

### Добавление сервера в каталог

Двухшаговый процесс:

1. **Разворачиваем сам VPN-сервер** (Docker-образ из `docker/Dockerfile` с
   тегами `chimera_utls chimera_quic`, либо вручную бинарём `chimera server`
   как в примере выше) — `internal/provision.SSHDeployer` умеет сделать это
   по SSH на чистую VPS автоматически (ставит Docker, поднимает контейнер,
   генерирует X25519-ключ прямо на сервере).
2. **Регистрируем результат в каталоге:**

   ```bash
   chimera-control-cli catalog add \
       -host vps.example.com -port 443 \
       -pubkey <ПУБЛИЧНЫЙ_КЛЮЧ_СЕРВЕРА> \
       -sni www.microsoft.com -fp chrome \
       -country Sweden -city Stockholm
   chimera-control-cli catalog list
   chimera-control-cli catalog remove -id 3
   ```

Управление ключами и каталогом **сознательно** живёт только в CLI, а не в
HTTP-ручке общего назначения и не в отдельной admin-сборке приложения —
меньше поверхность атаки, чем раздавать привилегированные креды в
клиентском/операторском GUI-билде. Если в будущем понадобится веб-панель
для управления флотом — это должно быть отдельное web-приложение поверх
admin API, а не режим Flutter-клиента.

### Как клиент получает список серверов

`GET /v1/catalog` — требует валидный токен (список серверов не отдаётся
анонимно). Возвращает JSON-массив
`[{host, port, pubkey, sni, fp, country, city, load_pct, healthy}]`,
отсортированный "здоровые и наименее загруженные — первыми". Приложение
опрашивает эту ручку при открытии экрана выбора сервера, кэширует последний
успешный ответ в памяти (устойчивость к кратковременным сбоям
control-plane).

## Приложение (Windows tray)

`app/` — Flutter-трей для Windows поверх Go-ядра, с графическим интерфейсом
для управления подключением и сетевой защитой. Поведение трея —
Mullvad-style: клик по иконке открывает/закрывает окно рядом с иконкой,
контекстное меню — по ПКМ. Иконка в трее и минимальное меню (`Open`/`Quit`)
появляются сразу при старте приложения, ещё до входа в аккаунт — экран ввода
ключа тоже открывается автоматически при первом запуске.

**Вход и выбор сервера** — доступ только по account-ключу (см. выше):
1. Первый запуск — экран ввода 16-символьного ключа
   (`account_entry_page.dart`), обменивает его на токен через control-plane.
2. «Choose server» открывает куррированный каталог (`catalog_page.dart`) —
   поиск по городу/стране, избранное, статус нагрузки/здоровья. Ручной ввод
   `chimera://`-ссылки, SSH-автодеплой и управление пользователями сервера
   **убраны из обычной сборки приложения** (см. выше про admin CLI) —
   куррированный список серверов теперь единственный способ выбрать сервер в
   UI. Соответствующая Go-логика (`internal/provision`, `internal/admin`)
   никуда не делась, она просто больше не вызывается из клиентского UI.
3. «Anti-censorship» (`anticensorship_page.dart`) — выбор транспорта
   (Reality / QUIC/H3 / Shadowsocks-AEAD / DNS-over-TCP) глобально для всех
   подключений.
4. «Account» — статус ключа, срок действия, число устройств, выход.

Full-tunnel-защита работает через `chimera-helper` — постоянную Windows-службу
(LocalSystem), которая один раз запрашивает права администратора при установке
и дальше поднимает/гасит туннель, маршруты, DNS и killswitch без UAC-промпта
на каждый Connect. Без неё то же самое работает через прямой вызов CLI с
подтверждением UAC на каждое действие — просто чуть менее гладко.

### Установка

Собрать одной командой (нужны: [Flutter SDK](https://docs.flutter.dev/get-started/install/windows),
Go, MinGW-w64/gcc — `winget install --id BrechtSanders.WinLibs.POSIX.UCRT -e`,
и [Inno Setup](https://jrsoftware.org/isinfo.php) — `winget install --id JRSoftware.InnoSetup -e`
— для сборки установщика). Если `flutter` не в `PATH`, укажите путь явно:

```powershell
.\scripts\build-app-windows.ps1 -Flutter "C:\tools\flutter\bin\flutter.bat"
```

Результат — **`dist\chimera_setup.exe`**, однофайловый установщик: тихо
ставит VC++ Redistributable, копирует приложение в `Program Files`,
регистрирует и стартует `chimera-helper`, создаёт ярлыки. Деинсталляция
(через «Программы и компоненты») полностью подчищает за собой — восстанавливает
сетевые настройки, останавливает и удаляет службу, завершает все процессы
приложения и стирает всё, что оно писало вне `Program Files` (включая
`%ProgramData%\chimera` и `%AppData%\com.chimera` с сохранёнными серверами и
аккаунтом) — после удаления в системе не остаётся ни запущенного процесса,
ни файлов.

Промежуточный артефакт `chimera_tray\` (плоская папка с `chimera_tray.exe`,
`chimera.dll`, `flutter_windows.dll`, плагиновыми `.dll` и `data\`) тоже
собирается по пути и годится для запуска без установки — но именно
`chimera_setup.exe` предназначен для раздачи пользователям.

Адрес control-plane, к которому обращается приложение, задаётся константой
`kDefaultControlPlaneMirrors` в `app/lib/account_store.dart` (список
зеркал — приложение перебирает их по очереди, чтобы блокировка основного
домена не отрезала пользователя от возможности активировать ключ).

## Ограничения текущей версии

- TLS-отпечаток авторизованной сессии пока не идентичен настоящему Chrome —
  это делает трафик менее неотличимым от обычного HTTPS к steal-host, чем в
  полной реализации Reality.
- Killswitch на Windows реализован через правила брандмауэра
  (`New-NetFirewallRule` + `DefaultOutboundAction Block`), а не через
  низкоуровневый WFP-драйвер — по эффекту эквивалентно, но менее
  «нативно», чем у части VPN-клиентов.
- `-auth-mode controlplane` пока не работает на QUIC-транспорте (только
  TCP-Reality) — QUIC-паритет для этого режима в разработке.
- `chimera-control` не поднимает TLS сам — публичный порт нужно прятать за
  реверс-прокси с сертификатом, если инстанс смотрит в интернет напрямую.
- Мобильных приложений (Android/iOS) пока нет; Go-ядро уже готово для этого
  (`mobile/bind.go`), но UI не реализован.

## Структура

```text
cmd/chimera/             CLI (keygen, link, qr, server, proxy, connect, tun, health)
cmd/chimera-control/     control-plane сервис: ключи доступа + каталог серверов
cmd/chimera-control-cli/ операторский CLI для control-plane (account/catalog/revoke)
cmd/chimera-helper/      Windows-служба: full-tunnel без UAC на каждый Connect
internal/controlplane/   аккаунты, токены (Ed25519), каталог, admin API, БД (SQLite)
internal/                транспорт, крипто, сервер, TUN, автопул эндпоинтов, провижининг VPS
app/                     Flutter-приложение для Windows (трей): аккаунт, каталог, anti-censorship
desktop/cffi/            C ABI между Go-ядром и приложением (dart:ffi)
docker/                  Dockerfile для серверного развёртывания, netem-бенчмарк
scripts/                 build/verify-скрипты для Linux/macOS/Windows + windows-installer.iss
docs/                    дизайн-доки по отдельным подсистемам (netstack, Reality, FEC, ...)
```
