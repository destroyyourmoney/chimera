# CHIMERA

**Адаптивный транспорт против цензуры.** CHIMERA совмещает stealth-идею Reality
(прозрачный fallback, Chrome-like ClientHello) с устойчивостью к потерям и
адаптивным выбором transport/endpoints.

| | Stealth (пробинг + отпечаток) | Устойчивость к потерям | Адаптация |
|---|:---:|:---:|:---:|
| **VLESS-Reality** | глубокий, но TCP-only | умирает на троттлинге | нет |
| **Hysteria 2** | палится по QUIC-отпечатку | rate-based CC | нет |
| **CHIMERA** | Reality-класс на TCP, uTLS Chrome по тегу | QUIC/ElasticCC по тегу | auto QUIC/TCP, failover, telemetry |

Один Go-бинарь, `CGO_ENABLED=0`, без внешних зависимостей на клиенте.

**Содержание:** [Сборка](#сборка) · [Запуск туннеля](#запуск-туннеля) ·
[Приложение (Windows tray)](#приложение-windows-tray) ·
[Ограничения текущей версии](#ограничения-текущей-версии) · [Структура](#структура)

---

## Сборка

```bash
./scripts/build.sh     # Linux/macOS → bin/chimera (CLI)
```
```powershell
.\scripts\build-app-windows.ps1     # Windows → dist\chimera_setup.exe (установщик)
```

`build.sh` собирает CLI-бинарь со всеми фичами сразу (Chrome-отпечаток TLS,
QUIC-транспорт, полный TUN-туннель). `build-app-windows.ps1` собирает
графическое Windows-приложение целиком, вплоть до готового установщика
(детали и требования — в разделе [«Приложение»](#приложение-windows-tray)
ниже); чистый CLI под Windows, `bin\chimera.exe`, при необходимости
собирается тем же `build.ps1`.

## Запуск туннеля

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

На Windows используйте `bin\chimera.exe` после `.\scripts\build.ps1` — эта сборка
уже включает full-tunnel режим, отдельно ничего досоставлять не нужно:

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

## Приложение (Windows tray)

`app/` — Flutter-трей для Windows поверх Go-ядра, с графическим интерфейсом
для управления серверами, подключением и сетевой защитой — не обязательно
работать через CLI. Поведение трея — Mullvad-style: клик по иконке
открывает/закрывает окно рядом с иконкой, контекстное меню — по ПКМ.

Добавить сервер можно тремя способами:
- вставить готовую `chimera://` ссылку или отсканировать QR;
- ввести данные вручную (host/публичный ключ/short ID и т.д.);
- указать IP и SSH-логин от чистого сервера — приложение само установит
  CHIMERA и сгенерирует ключи на самом сервере (идемпотентно: повторный
  деплой на тот же порт сам снесёт свой же старый контейнер, а не упадёт
  с «порт занят»).

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
`%ProgramData%\chimera` и `%AppData%\com.chimera` с сохранёнными серверами) —
после удаления в системе не остаётся ни запущенного процесса, ни файлов.

Промежуточный артефакт `chimera_tray\` (плоская папка с `chimera_tray.exe`,
`chimera.dll`, `flutter_windows.dll`, плагиновыми `.dll` и `data\`) тоже
собирается по пути и годится для запуска без установки — но именно
`chimera_setup.exe` предназначен для раздачи пользователям.

## Ограничения текущей версии

- TLS-отпечаток авторизованной сессии пока не идентичен настоящему Chrome —
  это делает трафик менее неотличимым от обычного HTTPS к steal-host, чем в
  полной реализации Reality.
- Killswitch на Windows реализован через правила брандмауэра
  (`New-NetFirewallRule` + `DefaultOutboundAction Block`), а не через
  низкоуровневый WFP-драйвер — по эффекту эквивалентно, но менее
  «нативно», чем у части VPN-клиентов.
- Мобильных приложений (Android/iOS) пока нет; Go-ядро уже готово для этого
  (`mobile/bind.go`), но UI не реализован.

## Структура

```text
cmd/chimera/         CLI (keygen, link, qr, server, proxy, connect, tun, health)
cmd/chimera-helper/  Windows-служба: full-tunnel без UAC на каждый Connect
internal/            транспорт, крипто, сервер, TUN, автопул эндпоинтов, провижининг VPS
app/                 Flutter-приложение для Windows (трей)
desktop/cffi/        C ABI между Go-ядром и приложением (dart:ffi)
docker/              Dockerfile для серверного развёртывания, netem-бенчмарк
scripts/             build/verify-скрипты для Linux/macOS/Windows + windows-installer.iss
docs/                дизайн-доки по отдельным подсистемам (netstack, Reality, FEC, ...)
```
