# CHIMERA

**Адаптивный транспорт против цензуры.** CHIMERA совмещает stealth-идею Reality
(прозрачный fallback, Chrome-like ClientHello) с устойчивостью к потерям и
адаптивным выбором transport/endpoints.

| | Stealth (пробинг + отпечаток) | Устойчивость к потерям | Адаптация |
|---|---|---|---|
| **VLESS-Reality** | глубокий, но TCP-only | умирает на троттлинге | нет |
| **Hysteria 2** | палится по QUIC-отпечатку | rate-based CC | нет |
| **CHIMERA** | Reality-класс на TCP, uTLS Chrome по тегу | QUIC/ElasticCC по тегу | auto QUIC/TCP, failover, telemetry |

Один Go-бинарь, `CGO_ENABLED=0`, без внешних зависимостей на клиенте.

## Сборка

```bash
./scripts/build.sh     # Linux/macOS → bin/chimera (CLI)
```
```powershell
.\scripts\build-app-windows.ps1     # Windows → chimera_tray\ (графическое приложение)
```

`build.sh` собирает CLI-бинарь со всеми фичами сразу (Chrome-отпечаток TLS,
QUIC-транспорт, полный TUN-туннель).
`build-app-windows.ps1` собирает графическое Windows-приложение (детали и
требования — в разделе «Приложение» ниже); чистый CLI под Windows,
`bin\chimera.exe`, при необходимости собирается тем же `build.ps1`.

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
добавляет правила, блокирующие утечку DNS мимо туннеля. `-setup-restore`
откатывает все сетевые изменения вручную, если что-то пошло не так.

⚠ **Сервер и клиент обязаны быть собраны из одной и той же версии** — при
рассинхроне поддерживаемых транспортов CLI явно скажет, какой флаг пересобрать.

## Приложение (Windows tray)

`app/` — Flutter-трей для Windows поверх Go-ядра, с графическим интерфейсом
для управления серверами, подключением и сетевой защитой — не обязательно
работать через CLI. Поведение трея — Mullvad-style: клик по иконке
открывает/закрывает окно рядом с иконкой, контекстное меню — по ПКМ.

Добавить сервер можно тремя способами:
- вставить готовую `chimera://` ссылку или отсканировать QR;
- ввести данные вручную (host/публичный ключ/short ID и т.д.);
- указать IP и SSH-логин от чистого сервера — приложение само установит
  CHIMERA и сгенерирует ключи на самом сервере.

Собрать одной командой (нужны: [Flutter SDK](https://docs.flutter.dev/get-started/install/windows),
Go, и MinGW-w64/gcc — `winget install --id BrechtSanders.WinLibs.POSIX.UCRT -e`,
если ещё не стоит). Если `flutter` не в `PATH`, укажите путь явно:

```powershell
.\scripts\build-app-windows.ps1 -Flutter "C:\tools\flutter\bin\flutter.bat"
```

Результат — папка `chimera_tray\` с `chimera_tray.exe` и всем необходимым
рядом (`chimera.dll`, `flutter_windows.dll`, плагиновые `.dll`, `data/`).
Это не однофайловый exe — переносить и запускать нужно всю папку целиком.

## Ограничения текущей версии

- TLS-отпечаток авторизованной сессии пока не идентичен настоящему Chrome —
  это делает трафик менее неотличимым от обычного HTTPS к steal-host, чем в
  полной реализации Reality.
- Постоянный service-helper и полный WFP killswitch на Windows ещё не
  реализованы — есть DNS leak guard и route-based защита на время сессии.
- Мобильных приложений (Android/iOS) пока нет; Go-ядро уже готово для этого
  (`mobile/bind.go`), но UI не реализован.

## Структура

```text
cmd/chimera/     CLI (keygen, link, qr, server, proxy, connect, tun, health)
internal/        транспорт, крипто, сервер, TUN, автопул эндпоинтов
app/             Flutter-приложение для Windows (трей)
desktop/cffi/    C ABI между Go-ядром и приложением (dart:ffi)
docker/          Dockerfile для серверного развёртывания, netem-бенчмарк
scripts/         build/verify-скрипты для Linux/macOS/Windows
```
