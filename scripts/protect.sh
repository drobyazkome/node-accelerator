#!/usr/bin/env bash
#
# protect.sh — 🛡 Защита ноды.
#   • nftables (своя таблица inet na_filter, БЕЗ flush ruleset — сосуществует с
#     CrowdSec-bouncer и Docker-NAT):
#       AntiScan (portscan→autoban), flag-drop (XMAS/NULL/SYN+FIN/SYN+RST/FIN+RST/…),
#       anti-spoofing (bogon на WAN), SYN-flood + UDP-flood (per-IP rate-limit),
#       connect-flood SSH (per-IP→бан), per-IP connlimit (ct count), ICMP rate-limit.
#   • CrowdSec + crowdsec-firewall-bouncer-nftables — поведенческий IPS и community-блоклист.
#   • Авто-whitelist IP, с которого ты сейчас по SSH + сейфти-таймер от самоблокировки.
#
# Откат: scripts/rollback.sh protect
#
# ENV (всё опционально):
#   SSH_PORT, TCP_PORTS=443,2087, UDP_PORTS=443,2087
#   NODE_PORT=auto                     порт(ы) node-agent через запятую; auto = детект с
#                                      ноды (env контейнера remnawave/node → .env → ss),
#                                      не нашлось → оба известных дефолта 2222,3000
#   NODE_PORT_AUTOWL=auto              при whitelist-only пускать текущих established-пиров
#                                      node-порта отдельным сетом na_nodeport_wl_* (анти-
#                                      самоотстрел панели); auto|0|1
#   WHITELIST="1.2.3.4,5.6.7.0/24"     IP/CIDR панели/мониторинга (v4 и v6)
#   SYN_RATE=200  SYN_BURST=400        per-IP лимит новых TCP-конн./сек на сервисный порт
#   UDP_RATE=200  UDP_BURST=400        per-IP лимит UDP пакетов/сек
#   UDP_BULK_PORTS=443                  порты объёмного UDP (HY2/TUIC) — свой лимит
#   UDP_BULK_RATE=50000 UDP_BULK_BURST=100000   per-IP лимит для них
#   CONN_LIMIT=2048                    макс. одновременных конн. с одного IP (ct count)
#   SSH_RATE=6    SSH_BURST=5          per-IP новых SSH/мин до бана
#   SSH_BAN_TIME=24h  PORTSCAN_BAN_TIME=1h
#   ENABLE_PORTSCAN_BAN=1  ENABLE_CROWDSEC=1  ENABLE_SYNPROXY=0
#   CROWDSEC_STRICT=0                  1 = ставить CrowdSec ТОЛЬКО из пиннингованного
#                                      APT-репо; не поднялся — пропустить (без curl|bash)
#   FW_MODE=strict|open|skip           strict: блок всех портов, кроме разрешённых (дефолт);
#                                      open: защита без блокировки прочих портов (3x-ui);
#                                      skip: nftables не трогать вообще (только CrowdSec)
#   CROWDSEC_ENROLL_KEY=...            enroll в CrowdSec Console (опц.)
#   SAFETY_DELAY=300  DRY_RUN=0  REMNAWAVE_NONINTERACTIVE=1

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_root
detect_os

# Один прогон protect за раз. Параллельные запуски (оркестратор из панели + руками)
# не рвут nft-транзакцию, но перекрываются сейфти-таймером: таймер прогона A удалит
# таблицу, которую прогон B уже применил и подтвердил. NA_NO_LOCK=1 — отключить.
if [[ "${NA_NO_LOCK:-0}" != "1" ]] && command -v flock >/dev/null 2>&1 && mkdir -p "$STATE_DIR" 2>/dev/null; then
    exec 9>"$STATE_DIR/protect.lock"
    flock -n 9 || { err "уже идёт другой прогон protect.sh (лок $STATE_DIR/protect.lock) — не мешаю"; exit 1; }
fi

BACKUP="$(backup_dir)"

# Подхватываем сохранённый конфиг ноды (если есть): ре-ран без ENV не сбрасывает
# поднятые под эту ноду ручки на дефолты. ENV по-прежнему всё переопределяет.
load_conf "$CONF_DIR/protect.conf"

# ─── Параметры ───────────────────────────────────────────────────────────────
SSH_PORT="${SSH_PORT:-$(detect_ssh_port)}"
TCP_PORTS="${TCP_PORTS:-443,2087}"
UDP_PORTS="${UDP_PORTS:-443,2087}"
# Порт(ы) node-agent. 'auto' (дефолт) = взять с самой ноды: env работающего контейнера
# remnawave/node → .env compose-каталога → ss (процесс rw-node). Remnawave node 2.x
# слушает :3000, старые гайды ставили :2222 — захардкоженный дефолт при несовпадении
# МОЛЧА отрезал панель от ноды (strict: не перечисленный порт падает в catch-all drop).
# Детект не нашёл ничего и прошлых прогонов не было → правила на ОБА дефолта (2222,3000).
NODE_PORT="${NODE_PORT:-auto}"
NODE_PORT_FALLBACK="2222,3000"
NODE_PORT_LAST="${NODE_PORT_LAST:-}"    # кэш последнего удачного детекта (persist)
WHITELIST="${WHITELIST:-}"
SYN_RATE="${SYN_RATE:-200}";  SYN_BURST="${SYN_BURST:-400}"
UDP_RATE="${UDP_RATE:-200}";  UDP_BURST="${UDP_BURST:-400}"
# Порты с легитимным объёмным UDP (Hysteria2/TUIC): общий UDP_RATE их душит,
# поэтому у них отдельный, намного более высокий per-IP потолок.
UDP_BULK_PORTS="${UDP_BULK_PORTS:-}"
UDP_BULK_RATE="${UDP_BULK_RATE:-50000}"; UDP_BULK_BURST="${UDP_BULK_BURST:-100000}"
# CONN_LIMIT — потолок ОДНОВРЕМЕННЫХ конн. с одного IP. За CGNAT (мобильные операторы,
# частый кейс в RU/IR) один egress-IP агрегирует много абонентов → держим с большим
# запасом, чтобы не рубить целые операторские пулы. Реальный VLESS-юзер — десятки конн.
CONN_LIMIT="${CONN_LIMIT:-2048}"
ICMP_RATE="${ICMP_RATE:-10}"; ICMP_BURST="${ICMP_BURST:-20}"   # PER-IP (не глобально)
SSH_RATE="${SSH_RATE:-6}";    SSH_BURST="${SSH_BURST:-5}"
SSH_BAN_TIME="${SSH_BAN_TIME:-24h}"
PORTSCAN_BAN_TIME="${PORTSCAN_BAN_TIME:-1h}"
# Порог автобана за скан: банить IP только если он бьёт по закрытым портам БЫСТРЕЕ
# порога (реальный сканер). Одиночные шальные SYN из CGNAT-пула не банят весь оператор.
PORTSCAN_RATE="${PORTSCAN_RATE:-15}"; PORTSCAN_BURST="${PORTSCAN_BURST:-30}"  # /minute, per-IP
ENABLE_PORTSCAN_BAN="${ENABLE_PORTSCAN_BAN:-1}"
ENABLE_CROWDSEC="${ENABLE_CROWDSEC:-1}"
# CROWDSEC_STRICT=1 — никакого curl|bash-фоллбэка: не поднялся пиннингованный репо,
# значит CrowdSec просто не ставим. Фоллбэк форсируется атакующим (достаточно сделать
# packagecloud недостижимым — egress-фильтр, DNS), а это подмена проверенного по
# отпечатку APT-репо на неверифицированный код из сети, запускаемый root'ом.
CROWDSEC_STRICT="${CROWDSEC_STRICT:-0}"
ENABLE_SYNPROXY="${ENABLE_SYNPROXY:-0}"
# Режим файрвола:
#   strict — input policy drop: открыты ТОЛЬКО SSH/сервисные/node-agent порты
#            (Remnawave node: все нужные порты известны заранее).
#   open   — вся защита (bad-flags/анти-спуф/SYN+UDP-flood/SSH-бан/CrowdSec) активна,
#            но НЕ перечисленные порты НЕ блокируются (3x-ui: inbound-порты создаются
#            из панели динамически — strict их молча отрезал бы).
#   skip   — nftables-файрвол не ставится вообще (CrowdSec/ctguard — по своим флагам);
#            печатаем инструкцию, как закрыть порты вручную.
# Пусто = спросить интерактивно (с автодетектом 3x-ui); неинтерактивно = strict.
FW_MODE="${FW_MODE:-}"
SAFETY_DELAY="${SAFETY_DELAY:-300}"
DRY_RUN="${DRY_RUN:-0}"
WAN="$(default_iface || true)"

# ── v3.0: ban-once, защита node-port, блоклисты, fleet-sync, ctguard ──────────
# ban-once: первое нарушение → suspect (наблюдение, без drop), второе в окне →
# confirmed (drop). Режет ложные баны за CGNAT. 1=вкл (дефолт), 0=сразу банить.
ENABLE_BANONCE="${ENABLE_BANONCE:-1}"
SUSPECT_TIME="${SUSPECT_TIME:-30m}"        # окно наблюдения за «подозреваемым»
# node-agent порт: открыт миру (мягкий лимит) или только whitelist. 'auto' =
# whitelist-only, если оператор задал WHITELIST (значит, знает свой доверенный набор);
# если WHITELIST пуст — оставляем мягкий лимит, чтобы не отрезать неизвестную панель.
NODE_PORT_WHITELIST_ONLY="${NODE_PORT_WHITELIST_ONLY:-auto}"
# Анти-самоотстрел панели: при whitelist-only текущие established-пиры node-порта
# (= панель, даже если её IP забыли в WHITELIST) пускаются отдельным сетом
# na_nodeport_wl_* (ТОЛЬКО этот порт, не общий whitelist) и персистятся. 'auto' =
# включено, когда whitelist-only ВЫВЕЛСЯ сам из заданного WHITELIST; при явном
# NODE_PORT_WHITELIST_ONLY=1 уважаем строгий intent (только warn). 1=форс, 0=выкл.
NODE_PORT_AUTOWL="${NODE_PORT_AUTOWL:-auto}"
NODE_PORT_PEERS="${NODE_PORT_PEERS:-}"   # персист авто-подхваченных пиров (IP через ,)
# Статич-блоклисты (Spamhaus DROP + FireHOL L1 [+ Tor]) — opt-in, обновляются таймером.
ENABLE_BLOCKLISTS="${ENABLE_BLOCKLISTS:-0}"
BLOCK_TOR="${BLOCK_TOR:-0}"
BLOCKLIST_REFRESH="${BLOCKLIST_REFRESH:-12h}"
# Масс-сканеры (Censys/Driftnet/ONYPHE/Shodan/Stretchoid и прочие индексаторы) — opt-in.
# Два источника, СОЗНАТЕЛЬНО разной природы:
#   1) ASN-лист — только организации, ЧЬЁ ЕДИНСТВЕННОЕ ЗАНЯТИЕ сканирование. Префиксы
#      резолвятся по RIPEstat (HTTPS) с фолбэком на whois RADB (TCP/43 режут у части
#      хостеров). Крупные облака сюда попадать НЕ ДОЛЖНЫ: сканер, арендовавший /24 в
#      GCP, не повод дропнуть 3457 префиксов Google.
#   2) Префикс-фиды — точечные диапазоны сканеров, живущих ВНУТРИ больших облаков
#      (Linode/Azure/DO/GCP). Их можно резать только по префиксу, не по ASN.
# Предохранитель от «ASN оказался облаком»: SCANNER_ASN_MAX_PREFIXES.
ENABLE_SCANNERS="${ENABLE_SCANNERS:-0}"
SCANNER_REFRESH="${SCANNER_REFRESH:-7d}"
SCANNER_ASN_SOURCE="${SCANNER_ASN_SOURCE:-auto}"      # auto|ripestat|whois
SCANNER_ASN_MAX_PREFIXES="${SCANNER_ASN_MAX_PREFIXES:-96}"  # ASN шире — пропустить целиком
SCANNER_MIN_PREFIXLEN="${SCANNER_MIN_PREFIXLEN:-16}"  # префикс короче /16 — отбросить
SCANNER_FEEDS="${SCANNER_FEEDS:-1}"                   # 1 = тянуть и префикс-фиды тоже
RIPESTAT_TIMEOUT="${RIPESTAT_TIMEOUT:-15}"
WHOIS_TIMEOUT="${WHOIS_TIMEOUT:-20}"
# Remnawave fleet auto-sync: ноды флота сами держат IP друг друга в whitelist.
# 'auto' = вкл при заданных REMNAWAVE_URL+TOKEN (или REMNAWAVE_NODES_URL); 1=форс; 0=выкл.
# REMNAWAVE_NODES_URL — альтернатива БЕЗ токена панели на ноде: статический JSON того же
# вида, что /api/nodes (панель публикует кроном, доступ ограничить basic-auth/allowlist),
# либо plain-text: адрес/hostname на строку, # — комментарий. Снимает blast-radius
# полноценного API-токена, лежащего на каждой ноде.
REMNAWAVE_URL="${REMNAWAVE_URL:-}"
REMNAWAVE_TOKEN="${REMNAWAVE_TOKEN:-}"
REMNAWAVE_NODES_URL="${REMNAWAVE_NODES_URL:-}"
# Caddy Security / Tiny Auth перед панелью → заголовок X-Api-Key (как subscription-page).
# REMNAWAVE_CADDY_TOKEN — алиас (bedolaga-бот); приоритет у CADDY_AUTH_API_TOKEN.
CADDY_AUTH_API_TOKEN="${CADDY_AUTH_API_TOKEN:-${REMNAWAVE_CADDY_TOKEN:-}}"
FLEET_SYNC="${FLEET_SYNC:-auto}"
FLEET_SYNC_INTERVAL="${FLEET_SYNC_INTERVAL:-5min}"
# conntrack phantom-eviction (защита от distributed connect-and-hold) — opt-in,
# по умолчанию observe-режим (только лог, без эвикта), включать осознанно.
ENABLE_CTGUARD="${ENABLE_CTGUARD:-0}"
NA_CTG_ENFORCE="${NA_CTG_ENFORCE:-0}"
NA_CTG_PHANTOM_MIN="${NA_CTG_PHANTOM_MIN:-4000}"  # conntrack-порог «холдера» (выше CGNAT-churn)
NA_CTG_LIVE_FLOOR="${NA_CTG_LIVE_FLOOR:-2}"       # ≤ столько живых сокетов = фантом
NA_CTG_COARSE_MULT="${NA_CTG_COARSE_MULT:-3}"     # дамп conntrack только если ct ≥ ss×N
NA_CTG_BANTIME="${NA_CTG_BANTIME:-15m}"
NA_CTG_INTERVAL="${NA_CTG_INTERVAL:-20s}"

# 3x-ui на этой машине? У него панель + inbound-порты создаются динамически —
# strict-файрвол молча отрежет всё, чего нет в TCP_PORTS/UDP_PORTS. Детект по
# типовым артефактам установщика 3x-ui/x-ui.
xui_detected() {
    [[ -f /etc/systemd/system/x-ui.service || -d /usr/local/x-ui ]] && return 0
    command -v x-ui >/dev/null 2>&1
}

if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" && "$DRY_RUN" != "1" && "${CROWDSEC_PROBE:-0}" != "1" ]]; then
    title "Параметры защиты"
    _fwdef="$FW_MODE"
    if [[ -z "$_fwdef" ]]; then _fwdef=strict; xui_detected && _fwdef=open; fi
    echo "Режим файрвола — блокировать ли все порты, кроме явно разрешённых:"
    echo "  1) strict — да: открыты только SSH + сервисные + node-agent порты"
    echo "              (Remnawave node: нужные порты известны заранее)"
    echo "  2) open   — нет: анти-флуд/баны/анти-спуф работают, прочие порты НЕ блокируются"
    echo "              (3x-ui: inbound-порты создаются из панели динамически)"
    echo "  3) skip   — файрвол не трогать вообще (только CrowdSec);"
    echo "              подскажу, как закрыть порты вручную"
    xui_detected && warn "Обнаружен 3x-ui: strict заблокирует панель и все не перечисленные inbound'ы!"
    _v=""; read -rp "Режим файрвола [1-3 или strict/open/skip, дефолт $_fwdef]: " _v || true
    case "${_v:-$_fwdef}" in
        1|strict) FW_MODE=strict;;
        2|open)   FW_MODE=open;;
        3|skip)   FW_MODE=skip;;
        *) warn "«$_v» не понял — беру $_fwdef"; FW_MODE="$_fwdef";;
    esac
    if [[ "$FW_MODE" != "skip" ]]; then
        read -rp "SSH порт                         [$SSH_PORT]: "  _v && SSH_PORT="${_v:-$SSH_PORT}"
        read -rp "TCP порты сервиса (через ,)       [$TCP_PORTS]: " _v && TCP_PORTS="${_v:-$TCP_PORTS}"
        read -rp "UDP порты сервиса (через ,)       [$UDP_PORTS]: " _v && UDP_PORTS="${_v:-$UDP_PORTS}"
        # node-agent порт — понятие Remnawave; в open-режиме его правила не ставятся
        [[ "$FW_MODE" == "strict" ]] && read -rp "Порт node-agent (auto = детект)  [$NODE_PORT]: " _v && NODE_PORT="${_v:-$NODE_PORT}"
    fi
    read -rp "Whitelist IP/CIDR (панель, твои)  [пусто]: "     _v && WHITELIST="${_v:-$WHITELIST}"
fi
# Неинтерактивно и без явного FW_MODE — strict (прежнее поведение не меняется).
[[ -z "$FW_MODE" ]] && FW_MODE=strict

# ─── Валидация ───────────────────────────────────────────────────────────────
_is_port()  { [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }
validate_port_list() {
    local v="$1" name="$2" p
    [[ -z "$v" ]] && return 0
    [[ "$v" =~ ^[0-9,]+$ ]] || { err "$name: '$v' — только цифры и запятые"; return 1; }
    for p in ${v//,/ }; do _is_port "$p" || { err "$name: '$p' вне 1..65535"; return 1; }; done
}
# SSH_PORT допускает список (sshd на двух портах — типичная миграция порта).
[[ -n "$SSH_PORT" ]] || { err "SSH_PORT пуст"; exit 1; }
validate_port_list "$SSH_PORT" SSH_PORT || exit 1
[[ "$NODE_PORT" == "auto" ]] || validate_port_list "$NODE_PORT" NODE_PORT || exit 1
validate_port_list "$TCP_PORTS" TCP_PORTS || exit 1
validate_port_list "$UDP_PORTS" UDP_PORTS || exit 1
# Пустой = класса объёмного UDP нет (нода без Hysteria2/TUIC) — это норма, не ошибка.
[[ -z "$UDP_BULK_PORTS" ]] || validate_port_list "$UDP_BULK_PORTS" UDP_BULK_PORTS || exit 1
# кэш прошлого детекта приходит из conf — битый молча сбрасываем (уйдёт в nft-ruleset)
validate_port_list "$NODE_PORT_LAST" NODE_PORT_LAST 2>/dev/null || NODE_PORT_LAST=""

# Числовые/duration параметры тоже валидируем: они разворачиваются в nft-ruleset и
# (SAFETY_DELAY) в sh-таймер. Тулкит параметризуется неинтерактивно из панели/оркестратора,
# поэтому непровалидированный ENV здесь — не «root сам себе», а реальный вектор.
_is_uint()     { [[ "$1" =~ ^[0-9]+$ ]]; }
_is_duration() { [[ "$1" =~ ^[0-9]+(s|m|h|d)?$ ]]; }
# systemd-time (OnUnitActiveSec): один числовой терм с опц. словом-единицей. Уходит
# в .timer-юнит → валидируем, чтобы непровалидированный ENV не дописал директив.
_is_systime()  { [[ "$1" =~ ^[0-9]+(s|sec|m|min|h|hr|d|day)?$ ]]; }
# UDP_BULK_PORTS сюда НЕ входит: это список портов ("443" или "443,8443"), а не
# число, и по умолчанию он пуст. В числовом цикле он валил ре-ран на любой ноде
# без Hysteria2 ещё до генерации правил. Порты проверяются своей валидацией ниже.
for _k in SYN_RATE SYN_BURST UDP_RATE UDP_BURST UDP_BULK_RATE UDP_BULK_BURST CONN_LIMIT ICMP_RATE ICMP_BURST \
          SSH_RATE SSH_BURST PORTSCAN_RATE PORTSCAN_BURST SAFETY_DELAY \
          NA_CTG_PHANTOM_MIN NA_CTG_LIVE_FLOOR NA_CTG_COARSE_MULT; do
    _is_uint "${!_k}" || { err "$_k='${!_k}' — ожидается целое число"; exit 1; }
done
for _k in SSH_BAN_TIME PORTSCAN_BAN_TIME SUSPECT_TIME NA_CTG_BANTIME; do
    _is_duration "${!_k}" || { err "$_k='${!_k}' — ожидается число с опц. суффиксом s|m|h|d"; exit 1; }
done
for _k in BLOCKLIST_REFRESH FLEET_SYNC_INTERVAL NA_CTG_INTERVAL SCANNER_REFRESH; do
    _is_systime "${!_k}" || { err "$_k='${!_k}' — ожидается systemd-интервал (напр. 12h, 5min)"; exit 1; }
done
# enum-флаги 0/1 (+auto где уместно)
for _k in ENABLE_PORTSCAN_BAN ENABLE_CROWDSEC ENABLE_SYNPROXY ENABLE_BANONCE \
          ENABLE_BLOCKLISTS BLOCK_TOR ENABLE_CTGUARD NA_CTG_ENFORCE CROWDSEC_STRICT \
          ENABLE_SCANNERS SCANNER_FEEDS; do
    [[ "${!_k}" =~ ^[01]$ ]] || { err "$_k='${!_k}' — ожидается 0 или 1"; exit 1; }
done
[[ "$SCANNER_ASN_SOURCE" =~ ^(auto|ripestat|whois)$ ]] || { err "SCANNER_ASN_SOURCE должно быть auto|ripestat|whois"; exit 1; }
for _k in SCANNER_ASN_MAX_PREFIXES SCANNER_MIN_PREFIXLEN RIPESTAT_TIMEOUT WHOIS_TIMEOUT; do
    [[ "${!_k}" =~ ^[0-9]+$ ]] || { err "$_k='${!_k}' — ожидается число"; exit 1; }
done
(( SCANNER_MIN_PREFIXLEN >= 8 && SCANNER_MIN_PREFIXLEN <= 32 )) || { err "SCANNER_MIN_PREFIXLEN вне 8..32"; exit 1; }
[[ "$NODE_PORT_WHITELIST_ONLY" =~ ^(auto|0|1)$ ]] || { err "NODE_PORT_WHITELIST_ONLY должно быть auto|0|1"; exit 1; }
[[ "$NODE_PORT_AUTOWL" =~ ^(auto|0|1)$ ]] || { err "NODE_PORT_AUTOWL должно быть auto|0|1"; exit 1; }
[[ "$FLEET_SYNC" =~ ^(auto|0|1)$ ]] || { err "FLEET_SYNC должно быть auto|0|1"; exit 1; }
[[ "$FW_MODE" =~ ^(strict|open|skip)$ ]] || { err "FW_MODE='$FW_MODE' — ожидается strict|open|skip"; exit 1; }
if [[ -n "$REMNAWAVE_URL" && ! "$REMNAWAVE_URL" =~ ^https?://[A-Za-z0-9._~:/?#=%@-]+$ ]]; then
    err "REMNAWAVE_URL='$REMNAWAVE_URL' — ожидается http(s)://… без спецсимволов"; exit 1
fi
if [[ -n "$REMNAWAVE_NODES_URL" && ! "$REMNAWAVE_NODES_URL" =~ ^https?://[A-Za-z0-9._~:/?#=%@-]+$ ]]; then
    err "REMNAWAVE_NODES_URL='$REMNAWAVE_NODES_URL' — ожидается http(s)://… без спецсимволов"; exit 1
fi
# http:// + секрет = токен уходит по проводу открытым текстом. Редирект-даунгрейд мы
# блокируем (--proto-redir), а вот явно заданную cleartext-схему запретить нельзя
# (бывают внутренние сети) — но молчать об этом нельзя тем более.
if [[ -n "$CADDY_AUTH_API_TOKEN" || -n "$REMNAWAVE_TOKEN" ]]; then
    for _u in "$REMNAWAVE_URL" "$REMNAWAVE_NODES_URL"; do
        [[ "$_u" == http://* ]] && warn "'$_u' по http:// — токен панели/Caddy уйдёт открытым текстом. Возьми https."
    done
    unset _u
fi
unset _k

# Порт ТЕКУЩЕЙ SSH-сессии — ground truth (sshd её уже принял, гадать не нужно). Если он
# не входит в SSH_PORT (ошибка детекта, протухший protect.conf, порт меняли между
# прогонами), strict уронил бы его в catch-all drop → после срабатывания сейфти вход
# закрыт. Открываем ОБА + громкий warn — та же логика, что для node-port в v3.8.
# В маркер уходит эффективный список, в protect.conf — intent оператора (SSH_PORT).
SSH_EFF="$SSH_PORT"
SSH_SESSION_PORT="$(ssh_session_port || true)"
if [[ -n "$SSH_SESSION_PORT" && ",$SSH_EFF," != *",$SSH_SESSION_PORT,"* ]]; then
    warn "твоя SSH-сессия пришла на :$SSH_SESSION_PORT, а SSH_PORT=$SSH_PORT — открываю ОБА (иначе локаут после сейфти); сверь и закрепи SSH_PORT=$SSH_SESSION_PORT"
    SSH_EFF="$SSH_EFF,$SSH_SESSION_PORT"
fi
SSH_NFT="${SSH_EFF//,/, }"

# Резолв NODE_PORT_WHITELIST_ONLY=auto: whitelist-only только если оператор задал
# WHITELIST (знает доверенный набор). Пустой WHITELIST → мягкий лимит (не отрезаем панель).
# NPWL_SRC помнит, откуда взялось решение: авто-вывод из WHITELIST vs явный intent
# оператора — от этого зависит дефолт авто-допуска пиров (NODE_PORT_AUTOWL=auto).
NPWL_SRC="explicit"
if [[ "$NODE_PORT_WHITELIST_ONLY" == "auto" ]]; then
    NPWL_SRC="auto"
    [[ -n "$WHITELIST" ]] && NODE_PORT_WHITELIST_ONLY=1 || NODE_PORT_WHITELIST_ONLY=0
fi

# strict на машине с 3x-ui — почти наверняка отрежет панель и inbound'ы. Громко.
if [[ "$FW_MODE" == "strict" ]] && xui_detected; then
    warn "Найден 3x-ui, а FW_MODE=strict: панель и inbound-порты вне TCP_PORTS/UDP_PORTS ($TCP_PORTS / $UDP_PORTS) будут ЗАБЛОКИРОВАНЫ."
    warn "Для 3x-ui обычно нужен FW_MODE=open, либо перечисли порт панели и ВСЕ inbound-порты в TCP_PORTS/UDP_PORTS."
fi
# FW_MODE=open: понятия «закрытый порт» нет — любой порт может оказаться inbound'ом.
# Анти-скан meter ловил бы легитимные коннекты к неперечисленным портам → баны юзеров,
# поэтому автобан за скан в open-режиме не ставится (само значение ENABLE_PORTSCAN_BAN
# не трогаем — при возврате на strict оно снова заработает).
if [[ "$FW_MODE" == "open" && "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
    info "FW_MODE=open: анти-скан автобан не ставится (нет закрытых портов — meter банил бы легитимный трафик на inbound-порты)"
fi

# whitelist → v4/v6
WL4=""; WL6=""
add_wl() {
    local x
    for x in ${1//,/ }; do
        [[ -z "$x" ]] && continue
        if [[ "$x" == *:* ]]; then
            # строго hex+двоеточия (+опц. /prefix) — иначе значение уходит дословно в
            # nft-heredoc 'elements = { ... }' и может дописать произвольные правила
            [[ "$x" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] || { err "WHITELIST: '$x' не валидный IPv6/CIDR"; return 1; }
            WL6+="${WL6:+, }$x"
        elif [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then WL4+="${WL4:+, }$x"
        else err "WHITELIST: '$x' не IPv4/IPv6/CIDR"; return 1; fi
    done
}
add_wl "$WHITELIST" || exit 1
ADMIN_IP="$(ssh_client_ip || true)"
if [[ -n "$ADMIN_IP" ]]; then
    add_wl "$ADMIN_IP" || true
    info "Авто-whitelist твоего SSH-IP: $ADMIN_IP (защита от самоблокировки)"
fi

# ─── Зависимости ─────────────────────────────────────────────────────────────
title "Зависимости"
apt_install nftables curl ca-certificates iproute2 gnupg
ok "ok"

# ─── CrowdSec: пиннингованный APT-репозиторий (supply-chain) ─────────────────
# Вместо curl|bash с install.crowdsec.net — их packagecloud-репо с проверкой ПОЛНОГО
# отпечатка ключа (64-битный keyid подделать дёшево) и экспортом в keyring РОВНО этого
# ключа (см. import_pinned_key).
# Порядок suite-кандидатов:
#   1. any/any — канон апстрима (их же install.crowdsec.net пишет именно его). Один
#      набор пакетов на все дистрибутивы, Release всегда есть;
#   2. <os>/<codename> — нативный suite, если он у них собран;
#   3. <os>/bookworm|noble — фоллбэк для свежих релизов.
# Почему any/any первым: под Debian 13 (trixie) suite debian/trixie у CrowdSec ПУСТОЙ —
# нет Release-файла (upstream issues #3834/#3909), а родной пакет самого Debian 13 —
# древний 1.4.6, который апстрим сам не рекомендует.
CROWDSEC_FP="6A89E3C2303A901A889971D3376ED5326E93CD0C"
setup_crowdsec_repo() {
    local keyring=/etc/apt/keyrings/crowdsec-archive-keyring.gpg
    local list=/etc/apt/sources.list.d/crowdsec.list
    local os="$OS_ID" codename fb tmpkey cand path suite seen="" okrepo=0
    codename="$(os_codename)"; [[ -n "$codename" ]] || codename=bookworm
    fb=bookworm; [[ "$os" == "ubuntu" ]] && fb=noble
    mkdir -p /etc/apt/keyrings
    tmpkey="$(mktemp)" || return 1
    if ! curl -fsSL --connect-timeout 5 --max-time 20 \
            https://packagecloud.io/crowdsec/crowdsec/gpgkey -o "$tmpkey"; then
        warn "ключ CrowdSec (packagecloud) недоступен"; rm -f "$tmpkey"; return 1
    fi
    if ! import_pinned_key "$tmpkey" "$CROWDSEC_FP" "$keyring"; then
        warn "ключ CrowdSec не сошёлся с отпечатком $CROWDSEC_FP — отказываюсь использовать"
        rm -f "$tmpkey"; return 1
    fi
    rm -f "$tmpkey"
    # ВАЖНО: обновляем ТОЛЬКО свой list. Глобальный `apt-get update` вернул бы rc≠0 из-за
    # ЛЮБОГО постороннего битого источника на боксе (протухший сторонний репо — типовой
    # съёмный VPS), и пиннинг ложно самоотключился бы на живом packagecloud. Скоуп через
    # Dir::Etc даёт вердикт именно о нашем репо.
    local -a UPDSC=(-o "Dir::Etc::sourcelist=$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0)
    for cand in "any any" "$os $codename" "$os $fb"; do
        path="${cand%% *}"; suite="${cand##* }"
        [[ ",$seen," == *",$path/$suite,"* ]] && continue
        seen+="${seen:+,}$path/$suite"
        echo "deb [signed-by=$keyring] https://packagecloud.io/crowdsec/crowdsec/$path $suite main" > "$list"
        if apt-get update -qq "${UPDSC[@]}" 2>/dev/null; then okrepo=1; break; fi
        warn "репо CrowdSec '$path $suite' не поднялся — пробую следующий вариант"
    done
    if [[ "$okrepo" != "1" ]]; then
        rm -f "$list"; apt-get update -qq 2>/dev/null || true; return 1
    fi
    # общий кэш подтянуть (наш list валиден); чужие битые источники тут не фатальны
    apt-get update -qq 2>/dev/null || true
    return 0
}

# PROBE: репозиторий+ключ+пакеты CrowdSec резолвятся на этой ОС, БЕЗ установки.
# Для CI-матрицы и ops-проверки совместимости (аналог XANMOD_PROBE в optimize.sh).
if [[ "${CROWDSEC_PROBE:-0}" == "1" ]]; then
    setup_crowdsec_repo || { err "CROWDSEC_PROBE: репозиторий не поднялся"; exit 1; }
    apt-cache show crowdsec >/dev/null 2>&1 \
        && ok "CROWDSEC_PROBE: пакет crowdsec резолвится" \
        || { err "CROWDSEC_PROBE: пакет crowdsec не резолвится"; exit 1; }
    apt-cache show crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
        && ok "CROWDSEC_PROBE: bouncer резолвится" \
        || warn "CROWDSEC_PROBE: crowdsec-firewall-bouncer-nftables не резолвится в этом suite"
    exit 0
fi

# ─── Сейфти-таймер: если потеряем SSH — снести нашу таблицу через N сек ───────
# Действие сработавшей подстраховки. Снимает и живую таблицу, И автозагрузку правил.
# Почему второе обязательно: раньше сейфти удалял ТОЛЬКО таблицу, а na-firewall.service
# оставался enabled — доступ возвращался, оператор видел живой бокс и уходил, а ПЕРВЫЙ
# ЖЕ ребут применял тот самый локаут-руллсет заново, теперь уже без всякого сейфти.
write_safety_revert() {
    cat > /usr/local/sbin/na-fw-safety-revert <<'SREV'
#!/bin/sh
# na-fw-safety-revert — аварийный откат файрвола (ставится protect.sh, снимается rollback).
/usr/sbin/nft delete table inet na_filter 2>/dev/null
# na_panic сам по себе запереть не может (policy accept, SSH исключён), но оставлять
# ужесточённые лимиты после аварийного отката смысла нет — сейфти снимает всё наше.
/usr/sbin/nft delete table inet na_panic 2>/dev/null
rm -f /var/lib/node-accelerator/panic.on 2>/dev/null
systemctl disable na-firewall.service >/dev/null 2>&1
mkdir -p /var/lib/node-accelerator 2>/dev/null
date +%s > /var/lib/node-accelerator/safety-fired.last 2>/dev/null
rm -f /var/lib/node-accelerator/na-fw-safety.pid 2>/dev/null
logger -t na-fw-safety "СЕЙФТИ СРАБОТАЛ: na_filter удалена, автозагрузка правил выключена — защиты сейчас НЕТ, нужен повторный прогон protect"
exit 0
SREV
    chmod +x /usr/local/sbin/na-fw-safety-revert
}

arm_safety() {
    [[ "$DRY_RUN" == "1" ]] && return 0
    title "Подстраховка от блокировки"
    warn "Если SSH отвалится — через ${SAFETY_DELAY}s na_filter удалится И автозагрузка правил выключится (доступ вернётся, в т.ч. после ребута)."
    write_safety_revert
    if command -v systemd-run >/dev/null 2>&1; then
        systemctl stop na-fw-safety.timer 2>/dev/null || true
        systemd-run --quiet --unit=na-fw-safety --on-active="${SAFETY_DELAY}s" \
            /usr/local/sbin/na-fw-safety-revert >/dev/null 2>&1 \
            && { ok "safety: systemd-таймер na-fw-safety на ${SAFETY_DELAY}s"; return 0; }
    fi
    # fallback (нет systemd-run): nohup-таймер. Стейт в $STATE_DIR (root-only), НЕ в общей
    # /tmp — убирает симлинк/TOCTOU через предсказуемый путь. SAFETY_DELAY и pid передаём
    # позиционными аргументами в sh -c (без интерполяции в строку оболочки).
    mkdir -p "$STATE_DIR"
    local pidf="$STATE_DIR/na-fw-safety.pid" logf="$STATE_DIR/na-fw-safety.log"
    [[ -f "$pidf" && ! -L "$pidf" ]] && { kill "$(cat "$pidf")" 2>/dev/null || true; }
    nohup sh -c 'sleep "$1"; /usr/local/sbin/na-fw-safety-revert 2>/dev/null; rm -f "$2"' \
        _ "$SAFETY_DELAY" "$pidf" >"$logf" 2>&1 &
    echo $! > "$pidf"
    ok "safety: nohup pid $(cat "$pidf")"
}
disarm_safety() {
    systemctl stop na-fw-safety.timer 2>/dev/null || true
    local pidf="$STATE_DIR/na-fw-safety.pid"
    [[ -f "$pidf" && ! -L "$pidf" ]] && { kill "$(cat "$pidf")" 2>/dev/null || true; rm -f "$pidf"; }
    rm -f /tmp/na-fw-safety.pid /tmp/na-fw-safety.log 2>/dev/null || true   # legacy-стейт старых версий
}

# ─── FW_MODE=skip: nftables-файрвол не ставим ────────────────────────────────
print_fw_howto() {
    info "Как закрыть порты самому, когда определишься со списком:"
    echo "  A) Этим же модулем (рекомендуется — + анти-скан/флуд/автобаны/анти-спуф):"
    echo "       FW_MODE=strict TCP_PORTS=443,8443 UDP_PORTS=443 bash install.sh protect"
    echo "     Для 3x-ui: перечисли порт панели (по умолч. 2053) и ВСЕ порты inbound'ов —"
    echo "     всё, чего нет в списке (кроме SSH), будет заблокировано."
    echo "  B) Вручную минимальным nftables-allowlist'ом:"
    echo "       nft add table inet my_fw"
    echo "       nft 'add chain inet my_fw input { type filter hook input priority 0; policy drop; }'"
    echo "       nft add rule inet my_fw input iif lo accept"
    echo "       nft add rule inet my_fw input ct state established,related accept"
    echo "       nft add rule inet my_fw input meta l4proto { icmp, ipv6-icmp } accept"
    echo "       nft add rule inet my_fw input tcp dport { 22, 443 } accept   # СНАЧАЛА впиши свой SSH-порт!"
    echo "       nft add rule inet my_fw input udp dport { 443 } accept"
    echo "     Персист через reboot: nft list ruleset > /etc/nftables.conf && systemctl enable nftables"
    echo "  C) Или ufw: ufw default deny incoming && ufw allow 22/tcp && ufw allow 443 && ufw enable"
}
if [[ "$FW_MODE" == "skip" ]]; then
    title "Файрвол (nftables)"
    warn "FW_MODE=skip: nftables-защита НЕ ставится — порты не блокируются, анти-скан/флуд-лимиты/автобаны выключены."
    print_fw_howto
    # Переключение strict→skip: старая na_filter сама не исчезнет — порты остались бы
    # заблокированы «непонятно чем». Интерактивно предлагаем снять, иначе громкий hint.
    if [[ "$DRY_RUN" != "1" ]] && { nft list table inet na_filter >/dev/null 2>&1 || [[ -f /etc/systemd/system/na-firewall.service ]]; }; then
        warn "Найден ранее установленный файрвол na_filter — FW_MODE=skip сам его НЕ удаляет."
        if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]] && confirm "Удалить na_filter сейчас (порты разблокируются)?"; then
            nft delete table inet na_filter 2>/dev/null || true
            systemctl disable --now na-firewall.service >/dev/null 2>&1 || true
            systemctl disable --now na-fleet-sync.timer na-blocklist.timer >/dev/null 2>&1 || true
            rm -f /etc/systemd/system/na-firewall.service "$CONF_DIR/na_filter.nft"
            systemctl daemon-reload 2>/dev/null || true
            ok "na_filter удалена, порты разблокированы (полный откат модуля: bash install.sh rollback protect)"
        else
            info "Оставил как есть. Снять целиком: bash install.sh rollback protect"
        fi
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        ok "DRY-RUN: FW_MODE=skip — генерировать нечего."
        exit 0
    fi
fi

# fleet-sync живёт в сетах таблицы na_filter → при FW_MODE=skip невозможен.
FLEET_ON=0
if [[ "$FW_MODE" != "skip" ]]; then
    case "$FLEET_SYNC" in
        1) FLEET_ON=1;;
        auto) { [[ -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ]] || [[ -n "$REMNAWAVE_NODES_URL" ]]; } && FLEET_ON=1 \
              || { [[ -f "$CONF_DIR/fleet.env" ]] && FLEET_ON=1; };;
    esac
elif [[ "$FLEET_SYNC" == "1" || -n "$REMNAWAVE_NODES_URL" || ( -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ) ]]; then
    info "FW_MODE=skip: fleet-sync живёт в сетах na_filter — пропущен"
fi
[[ "$FW_MODE" == "skip" && "$ENABLE_BLOCKLISTS" == "1" ]] && info "FW_MODE=skip: блоклисты живут в сетах na_filter — пропущены"
[[ "$FW_MODE" == "skip" && "$ENABLE_SCANNERS" == "1" ]] && info "FW_MODE=skip: сеты scanner_* живут в na_filter — блок сканеров пропущен"

# ═══ ФАЙРВОЛ (nftables) — весь блок до CrowdSec пропускается при FW_MODE=skip ═══
NP_EFF="$NODE_PORT"   # skip-режим: детект не гоняем, в маркер значение уходит как есть
if [[ "$FW_MODE" != "skip" ]]; then

# ─── Резолв NODE_PORT: auto → фактический порт node-агента ───────────────────
# Правило надёжности: панель никогда не должна МОЛЧА терять ноду из-за порта.
#   auto + детект ок     → детект (кэш в NODE_PORT_LAST на случай остановленного агента);
#   auto + агент молчит  → прошлый детект, иначе оба известных дефолта (2222,3000);
#   явный порт ≠ детекту → правила на ОБА + громкий warn (кейс миграции агента 2222→3000:
#                          сохранённый conf держал 2222, strict ронял :3000 в catch-all drop).
NP_DETECTED="$(detect_node_port || true)"
if [[ "$NODE_PORT" == "auto" ]]; then
    if [[ -n "$NP_DETECTED" ]]; then
        NP_EFF="$NP_DETECTED"
        ok "node-agent: автодетект порта → $NP_EFF"
    elif [[ -n "$NODE_PORT_LAST" ]]; then
        NP_EFF="$NODE_PORT_LAST"
        warn "node-agent сейчас не детектится (контейнер остановлен?) — беру прошлый детект: $NP_EFF"
    else
        NP_EFF="$NODE_PORT_FALLBACK"
        warn "node-agent не найден — правила на оба известных дефолта ($NP_EFF); закрепить: NODE_PORT=<порт>"
    fi
else
    NP_EFF="$NODE_PORT"
    if [[ -n "$NP_DETECTED" ]]; then
        for _p in ${NP_DETECTED//,/ }; do
            if [[ ",$NP_EFF," != *",$_p,"* ]]; then
                NP_EFF+=",$_p"
                warn "node-agent фактически слушает :$_p (задан NODE_PORT=$NODE_PORT) — открываю ОБА, чтобы не отрезать панель; сверь и закрепи NODE_PORT"
            fi
        done
        unset _p
    fi
fi
[[ -n "$NP_DETECTED" ]] && NODE_PORT_LAST="$NP_DETECTED"
NP_NFT="${NP_EFF//,/, }"

# ─── Сборка per-port правил ──────────────────────────────────────────────────
TCP_RULES=""
for p in ${TCP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    TCP_RULES+="
        # порт ${p}: per-IP лимит одновременных коннектов (анти-exhaustion)
        tcp dport ${p} ct state new meter cc4_${p} { ip saddr ct count over ${CONN_LIMIT} } drop
        tcp dport ${p} ct state new meter cc6_${p} { ip6 saddr ct count over ${CONN_LIMIT} } drop
        # порт ${p}: per-IP SYN-rate (масштабируется по числу клиентов, не глобальный потолок)
        tcp dport ${p} ct state new meter syn4_${p} { ip saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        tcp dport ${p} ct state new meter syn6_${p} { ip6 saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        tcp dport ${p} ct state new limit rate 5/second log prefix \"[na synflood] \" level info
        tcp dport ${p} ct state new drop"
done

UDP_RULES=""
for p in ${UDP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    # Порты из UDP_BULK_PORTS несут полезный объёмный трафик (Hysteria2/TUIC), а не
    # запросы к сервису. Общий UDP_RATE=200 пакетов/с на IP — это потолок ~2 Мбит/с:
    # живой HY2 упирается в него мгновенно, пакеты уходят в drop, и клиент видит то
    # огромный пинг от ретрансмиссий, то N/A. Таким портам даём свой, высокий лимит:
    # он всё ещё режет настоящий флуд, но не мешает нормальной работе.
    local_rate="$UDP_RATE"; local_burst="$UDP_BURST"; _kind="анти-UDP-flood"
    if [[ ",${UDP_BULK_PORTS}," == *",${p},"* ]]; then
        local_rate="$UDP_BULK_RATE"; local_burst="$UDP_BULK_BURST"; _kind="объёмный UDP (HY2/TUIC)"
    fi
    UDP_RULES+="
        # порт ${p}/udp: per-IP rate — ${_kind}
        udp dport ${p} meter udp4_${p} { ip saddr limit rate ${local_rate}/second burst ${local_burst} packets } accept
        udp dport ${p} meter udp6_${p} { ip6 saddr limit rate ${local_rate}/second burst ${local_burst} packets } accept
        udp dport ${p} drop"
done

# anti-spoofing (только на WAN-интерфейсе)
ANTISPOOF=""
if [[ -n "$WAN" ]]; then
    ANTISPOOF="        # anti-spoofing: приватные/bogon источники на WAN = спуф
        udp sport 67 udp dport 68 accept
        iifname \"${WAN}\" ip saddr @bogon_v4 drop
        iifname \"${WAN}\" ip6 saddr @bogon_v6 drop"
fi

# node-agent порт: whitelist-only (drop мир) или мягкий per-IP лимит для неизвестных.
# FW_MODE=open: блок не ставим вовсе — node-agent это понятие Remnawave, а на 3x-ui
# NODE_PORT может оказаться чьим-то inbound'ом: скрытый drop/лимит именно на нём
# стал бы кошмаром при отладке.
#
# Анти-самоотстрел панели (whitelist-only): IP панели узнаётся ПО ФАКТУ — established-
# пиры node-порта (ss + conntrack: панель могла оказаться между keepalive-коннектами,
# «0 established в моменте» — норма) идут в отдельный сет na_nodeport_wl_* (допуск
# ТОЛЬКО к node-порту, НЕ общий whitelist) и персистятся в NODE_PORT_PEERS.
harvest_node_port_peers() {   # stdout: IP через запятую (v4/v6, без портов/скобок)
    local filt="" p
    for p in ${NP_EFF//,/ }; do filt="${filt:+$filt or }sport = :$p"; done
    [[ -n "$filt" ]] || return 0
    {
        ss -Hnt state established "( $filt )" 2>/dev/null | awk '{print $NF}' \
            | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//'
        if command -v conntrack >/dev/null 2>&1; then
            for p in ${NP_EFF//,/ }; do
                conntrack -L -p tcp --dport "$p" --state ESTABLISHED 2>/dev/null \
                    | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/){print substr($i,5); break}}'
            done
        fi
    } | sed -E 's/^::ffff:([0-9.]+)$/\1/' \
      | awk 'NF && $0!="127.0.0.1" && $0!="::1"' | sort -u | paste -sd, -
}
NPWL4=""; NPWL6=""
add_npwl() {   # как add_wl, но в сет только-node-порта; битые значения warn+skip (не fatal)
    local x
    for x in ${1//,/ }; do
        [[ -z "$x" ]] && continue
        if [[ "$x" == *:* ]]; then
            [[ "$x" =~ ^[0-9a-fA-F:]+$ ]] || { warn "node-port peers: '$x' не IPv6 — пропущен"; continue; }
            [[ ",$NPWL6," == *",$x,"* ]] || NPWL6+="${NPWL6:+,}$x"
        elif [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            [[ ",$NPWL4," == *",$x,"* ]] || NPWL4+="${NPWL4:+,}$x"
        else warn "node-port peers: '$x' не IP — пропущен"; fi
    done
}
NP_SETS=""
if [[ "$FW_MODE" == "open" ]]; then
    NODE_RULES=""
    [[ "$NODE_PORT_WHITELIST_ONLY" == "1" ]] && \
        info "FW_MODE=open: node-port правила не ставятся — NODE_PORT_WHITELIST_ONLY не действует (на 3x-ui порт(ы) ${NP_EFF} могут быть inbound'ом)"
elif [[ "$NODE_PORT_WHITELIST_ONLY" == "1" ]]; then
    # авто-допуск пиров: auto = вкл, когда whitelist-only ВЫВЕЛСЯ из WHITELIST;
    # явный NODE_PORT_WHITELIST_ONLY=1 — уважаем строгий intent (warn вместо допуска)
    NP_AUTOWL_ON=0
    case "$NODE_PORT_AUTOWL" in
        1) NP_AUTOWL_ON=1;;
        auto) [[ "$NPWL_SRC" == "auto" ]] && NP_AUTOWL_ON=1;;
    esac
    NP_FRESH="$(harvest_node_port_peers || true)"
    if [[ "$NP_AUTOWL_ON" == "1" ]]; then
        add_npwl "$NODE_PORT_PEERS"
        add_npwl "$NP_FRESH"
        NODE_PORT_PEERS="$NPWL4${NPWL4:+${NPWL6:+,}}$NPWL6"
        # cap: десятки «пиров» = это не контрол-порт панели (порт перепутан с сервисным?)
        _npc=0; for _p in ${NODE_PORT_PEERS//,/ }; do _npc=$((_npc+1)); done
        if (( _npc > 16 )); then
            warn "node-port peers: $_npc адресов — не похоже на контрол-порт панели; авто-допуск пропущен, проверь NODE_PORT"
            NPWL4=""; NPWL6=""; NODE_PORT_PEERS=""
        fi
        unset _npc _p
    fi
    NP_WL4_LINE=""; [[ -n "$NPWL4" ]] && NP_WL4_LINE="elements = { ${NPWL4//,/, } }"
    NP_WL6_LINE=""; [[ -n "$NPWL6" ]] && NP_WL6_LINE="elements = { ${NPWL6//,/, } }"
    NP_SETS="    set na_nodeport_wl_v4 { type ipv4_addr; $NP_WL4_LINE }
    set na_nodeport_wl_v6 { type ipv6_addr; $NP_WL6_LINE }"
    NODE_RULES="        # node-agent: ТОЛЬКО whitelist (общий — принят выше) + пиры панели из
        # @na_nodeport_wl_* (допуск лишь к этому порту) — остальным drop (контрол-порт не светим).
        # Пожарно пустить панель без ре-рана: nft add element inet na_filter na_nodeport_wl_v4 '{ <IP> }'
        tcp dport { ${NP_NFT} } ip  saddr @na_nodeport_wl_v4 accept
        tcp dport { ${NP_NFT} } ip6 saddr @na_nodeport_wl_v6 accept
        tcp dport { ${NP_NFT} } ct state new drop"
    info "node-agent порт(ы) ${NP_EFF}: whitelist-only (WHITELIST задан)"
    if [[ "$NP_AUTOWL_ON" == "1" && -n "$NODE_PORT_PEERS" ]]; then
        ok "node-agent: авто-допуск established-пиров (панель): $NODE_PORT_PEERS (сет na_nodeport_wl_*; выкл: NODE_PORT_AUTOWL=0)"
    elif [[ "$NP_AUTOWL_ON" != "1" && -n "$NP_FRESH" ]]; then
        warn "node-port сейчас держат коннект: $NP_FRESH — если среди них панель, добавь её в WHITELIST (или авто-допуск: NODE_PORT_AUTOWL=1)"
    elif [[ -z "$NP_FRESH" && -z "$NODE_PORT_PEERS" ]]; then
        warn "established-пиров node-порта не вижу — УБЕДИСЬ, что IP панели в WHITELIST, иначе нода отвалится от панели"
    fi
else
    NODE_RULES="        # node-agent: whitelist (выше) + мягкий per-IP лимит для неизвестных
        tcp dport { ${NP_NFT} } ct state new meter na4 { ip saddr limit rate 30/second burst 60 packets } accept
        tcp dport { ${NP_NFT} } ct state new meter na6 { ip6 saddr limit rate 30/second burst 60 packets } accept
        tcp dport { ${NP_NFT} } ct state new drop"
fi

# portscan → autoban (включается флагом). При ENABLE_BANONCE=1 — двухступенчато:
# 1-й быстрый скан → suspect (наблюдение, БЕЗ полного бана: скан-пакеты и так дропает
# финальный catch-all, но легит-трафик IP не режется), повторный в окне SUSPECT_TIME →
# confirmed-бан. Снимает ложные баны целых CGNAT-операторов из-за одного шального скана.
PORTSCAN=""
if [[ "$ENABLE_PORTSCAN_BAN" == "1" && "$FW_MODE" != "open" ]]; then
    _ps_log4="meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new limit rate 5/second log prefix \"[na portscan] \" level info"
    if [[ "$ENABLE_BANONCE" == "1" ]]; then
        PORTSCAN="        # ANTI-SCAN (ban-once): 1-й быстрый скан → suspect, 2-й в окне ${SUSPECT_TIME} → бан.
        $_ps_log4
        # уже suspect и снова бьёт быстрее порога → confirmed-бан
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new ip saddr @suspect_v4 meter psc4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v4 { ip saddr timeout ${PORTSCAN_BAN_TIME} } drop
        meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn ct state new ip6 saddr @suspect_v6 meter psc6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v6 { ip6 saddr timeout ${PORTSCAN_BAN_TIME} } drop
        # ещё не suspect и бьёт быстрее порога → пометить suspect (без бана; скан дропнет catch-all)
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @suspect_v4 { ip saddr timeout ${SUSPECT_TIME} }
        meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @suspect_v6 { ip6 saddr timeout ${SUSPECT_TIME} }"
    else
        PORTSCAN="        # ANTI-SCAN: бьёт по закрытым портам быстрее ${PORTSCAN_RATE}/min → бан ${PORTSCAN_BAN_TIME}.
        $_ps_log4
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v4 { ip saddr timeout ${PORTSCAN_BAN_TIME} } drop
        meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn ct state new meter ps6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } add @autoban_v6 { ip6 saddr timeout ${PORTSCAN_BAN_TIME} } drop"
    fi
fi

# ─── SYNPROXY (опционально, done-right) ──────────────────────────────────────
# ⚠️ На VPN-relay (профиль connect-and-hold / PPS-флуд) SYNPROXY обычно ИЗБЫТОЧЕН:
# его единственный реальный плюс — анти-спуф SYN — уже закрыт tcp_syncookies=1 +
# per-IP ct-лимитами (CONN_LIMIT/SYN_RATE), а издержки (обязательный be_liberal=1,
# per-packet overhead, поломка TFO на защищённых портах) не оправданы. Против самого
# распространённого вектора (connect-and-hold / реальный PPS) он не помогает вовсе.
# Поэтому default OFF; включать ТОЛЬКО под подтверждённый спуфнутый SYN-флуд. Оставлен
# opt-in для не-relay сценариев (голый L4-фронт без syncookies-достаточности).
#
# notrack ТОЛЬКО для трафика к самому хосту (fib daddr type local): иначе правило в
# prerouting цепляет conntrack/NAT ТРАНЗИТА (Docker-контейнер панели → удалённая нода)
# и ломает его. Требует ядро ≥5.14 + модуль nf_synproxy. Запрошен, но недоступен →
# fail-loud (маркер degraded + warn), БЕЗ тихой деградации; synproxy-правила не ставятся.
SYNPROXY_PRE=""; SYNPROXY_IN=""; SP_MODPROBE=""; SYNPROXY_OK=0
rm -f "$STATE_DIR/.synproxy-degraded" 2>/dev/null || true
if [[ "$ENABLE_SYNPROXY" == "1" ]]; then
    _kmaj="$(uname -r | cut -d. -f1)"; _kmin="$(uname -r | cut -d. -f2)"
    [[ "$_kmaj" =~ ^[0-9]+$ ]] || _kmaj=0; [[ "$_kmin" =~ ^[0-9]+$ ]] || _kmin=0
    if { [[ "$_kmaj" -gt 5 ]] || { [[ "$_kmaj" -eq 5 ]] && [[ "$_kmin" -ge 14 ]]; }; } && modprobe nf_synproxy 2>/dev/null; then
        SYNPROXY_OK=1
        SP_SET="$TCP_PORTS"
        # mss из MTU аплинка (−40Б IPv4+TCP), wscale 7 (дефолт Linux); клампим в 536..1460.
        _mtu="$(cat /sys/class/net/"$WAN"/mtu 2>/dev/null || echo 1500)"; [[ "$_mtu" =~ ^[0-9]+$ ]] || _mtu=1500
        SP_MSS=$(( _mtu - 40 )); { [[ "$SP_MSS" -gt 1460 ]] || [[ "$SP_MSS" -lt 536 ]]; } && SP_MSS=1460
        SP_MODPROBE="ExecStartPre=/bin/sh -c 'modprobe nf_synproxy 2>/dev/null || true'"
        SYNPROXY_PRE="    chain prerouting {
        type filter hook prerouting priority -300; policy accept;
        fib daddr type local tcp dport { ${SP_SET} } tcp flags syn notrack
    }"
        SYNPROXY_IN="        tcp dport { ${SP_SET} } ct state invalid,untracked synproxy mss ${SP_MSS} wscale 7 timestamp sack-perm"
        ok "SYNPROXY: ядро $(uname -r) ок, mss ${SP_MSS} wscale 7 (notrack только host-local)"
    else
        warn "SYNPROXY запрошен, но недоступен (нужно ядро ≥5.14 + модуль nf_synproxy). Защита БЕЗ synproxy."
        mkdir -p "$STATE_DIR"; echo "kernel=$(uname -r) reason=no_nf_synproxy at=$(date -Is)" > "$STATE_DIR/.synproxy-degraded"
    fi
fi

# ── Условные сеты/правила v3.0 (ban-once / blocklists / fleet) ────────────────
# suspect-сеты для ban-once (timeout + size-cap как у autoban).
SUSPECT_SETS=""
if [[ "$ENABLE_BANONCE" == "1" ]]; then
    SUSPECT_SETS="    set suspect_v4 { type ipv4_addr; flags timeout; size 65536; }
    set suspect_v6 { type ipv6_addr; flags timeout; size 65536; }"
fi

# blocklist-сеты (наполняет na-blocklist-update таймером) + drop-правило.
BLOCKLIST_SETS=""; BLOCKLIST_DROP=""
if [[ "$ENABLE_BLOCKLISTS" == "1" ]]; then
    BLOCKLIST_SETS="    set blocklist_v4 { type ipv4_addr; flags interval; auto-merge; }
    set blocklist_v6 { type ipv6_addr; flags interval; auto-merge; }"
    BLOCKLIST_DROP="        # статич-блоклисты (Spamhaus DROP / FireHOL L1 [/ Tor]) — обновляет na-blocklist-update
        ip  saddr @blocklist_v4 drop
        ip6 saddr @blocklist_v6 drop"
fi

# scanner-сеты (наполняет na-scanner-update таймером) + drop-правило.
SCANNER_SETS=""; SCANNER_DROP=""
if [[ "$ENABLE_SCANNERS" == "1" ]]; then
    SCANNER_SETS="    set scanner_v4 { type ipv4_addr; flags interval; auto-merge; }
    set scanner_v6 { type ipv6_addr; flags interval; auto-merge; }"
    SCANNER_DROP="        # масс-сканеры (ASN-лист + префикс-фиды) — обновляет na-scanner-update
        ip  saddr @scanner_v4 drop
        ip6 saddr @scanner_v6 drop"
fi

# fleet-сеты (наполняет na-fleet-sync с панели Remnawave) + accept сразу после whitelist.
# FLEET_ON резолвится выше (до блока файрвола — нужен и в skip-режиме).
FLEET_SETS=""; FLEET_ACCEPT=""
if [[ "$FLEET_ON" == "1" ]]; then
    FLEET_SETS="    set na_fleet_v4 { type ipv4_addr; flags interval; auto-merge; }
    set na_fleet_v6 { type ipv6_addr; flags interval; auto-merge; }"
    FLEET_ACCEPT="        # ноды флота (авто-синк с панели) — свои серверы, обходят все лимиты
        ip  saddr @na_fleet_v4 accept
        ip6 saddr @na_fleet_v6 accept"
fi

# SSH connect-flood: с ban-once (suspect→confirmed) или прямой бан.
if [[ "$ENABLE_BANONCE" == "1" ]]; then
    SSH_RULES="        # SSH connect-flood (ban-once): перебор → 1-й раз suspect+drop, 2-й в окне → бан ${SSH_BAN_TIME}
        tcp dport { ${SSH_NFT} } ct state new meter ssh4 { ip saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport { ${SSH_NFT} } ct state new meter ssh6 { ip6 saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport { ${SSH_NFT} } ct state new limit rate 5/second log prefix \"[na ssh-flood] \" level warn
        tcp dport { ${SSH_NFT} } ct state new ip saddr @suspect_v4 add @autoban_v4 { ip saddr timeout ${SSH_BAN_TIME} } drop
        tcp dport { ${SSH_NFT} } ct state new ip6 saddr @suspect_v6 add @autoban_v6 { ip6 saddr timeout ${SSH_BAN_TIME} } drop
        tcp dport { ${SSH_NFT} } ct state new meta nfproto ipv4 add @suspect_v4 { ip saddr timeout ${SUSPECT_TIME} } drop
        tcp dport { ${SSH_NFT} } ct state new meta nfproto ipv6 add @suspect_v6 { ip6 saddr timeout ${SUSPECT_TIME} } drop"
else
    SSH_RULES="        # SSH connect-flood: >${SSH_RATE}/мин новых с одного IP → бан ${SSH_BAN_TIME}
        tcp dport { ${SSH_NFT} } ct state new meter ssh4 { ip saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport { ${SSH_NFT} } ct state new meter ssh6 { ip6 saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport { ${SSH_NFT} } ct state new limit rate 5/second log prefix \"[na ssh-flood] \" level warn
        tcp dport { ${SSH_NFT} } ct state new meta nfproto ipv4 add @autoban_v4 { ip saddr timeout ${SSH_BAN_TIME} } drop
        tcp dport { ${SSH_NFT} } ct state new meta nfproto ipv6 add @autoban_v6 { ip6 saddr timeout ${SSH_BAN_TIME} } drop"
fi

WL4_LINE=""; [[ -n "$WL4" ]] && WL4_LINE="elements = { $WL4 }"
WL6_LINE=""; [[ -n "$WL6" ]] && WL6_LINE="elements = { $WL6 }"

# Финал input-цепочки по режиму: strict = policy drop + catch-all drop (всё не
# разрешённое блокируется); open = policy accept + catch-all: не перечисленные порты
# получают ТЕ ЖЕ per-IP флуд-лимиты, что и перечисленные выше (conn-limit / SYN-rate /
# UDP-rate; сверх лимита — транзитный drop пакета, НЕ бан IP), затем accept. Без этого
# динамические inbound'ы 3x-ui — ради которых open и существует — оставались бы совсем
# без анти-флуда. Прочие протоколы (ICMP отработан выше, GRE/ESP и т.п.) — accept.
FW_POLICY=drop
FW_CATCHALL="counter drop"
if [[ "$FW_MODE" == "open" ]]; then
    FW_POLICY=accept
    FW_CATCHALL="# FW_MODE=open: не перечисленные порты НЕ блокируются (динамические inbound'ы 3x-ui),
        # но per-IP лимиты им — те же, что перечисленным портам (drop сверх лимита ≠ бан)
        meta l4proto tcp ct state new meter occ4 { ip saddr ct count over ${CONN_LIMIT} } drop
        meta l4proto tcp ct state new meter occ6 { ip6 saddr ct count over ${CONN_LIMIT} } drop
        meta l4proto tcp ct state new meter osyn4 { ip saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        meta l4proto tcp ct state new meter osyn6 { ip6 saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        meta l4proto tcp ct state new limit rate 5/second log prefix \"[na synflood] \" level info
        meta l4proto tcp ct state new drop
        meta l4proto udp meter oudp4 { ip saddr limit rate ${UDP_RATE}/second burst ${UDP_BURST} packets } accept
        meta l4proto udp meter oudp6 { ip6 saddr limit rate ${UDP_RATE}/second burst ${UDP_BURST} packets } accept
        meta l4proto udp counter drop
        counter accept"
fi

# ─── Генерация nft-файла ─────────────────────────────────────────────────────
NFT_FILE="$CONF_DIR/na_filter.nft"
[[ "$DRY_RUN" == "1" ]] && NFT_FILE="$(mktemp /tmp/na_filter.XXXXXX.nft)"
mkdir -p "$CONF_DIR"
title "Генерация nftables → $NFT_FILE"

cat > "$NFT_FILE" <<NFT
#!/usr/sbin/nft -f
# node-accelerator / protect.sh @ $(date -Is)
# FW_MODE=$FW_MODE
# Управляем ТОЛЬКО своей таблицей — НЕ flush ruleset (живём рядом с CrowdSec/Docker).

table inet na_filter {}
delete table inet na_filter

table inet na_filter {

    set whitelist_v4 { type ipv4_addr; flags interval; auto-merge; $WL4_LINE }
    set whitelist_v6 { type ipv6_addr; flags interval; auto-merge; $WL6_LINE }

    # size — потолок записей: portscan-бан ловит чистый SYN (тривиально спуфится),
    # без лимита спуф-флуд раздул бы set в памяти ядра. При переполнении новые баны
    # просто не добавляются (старые живут по timeout).
    set autoban_v4 { type ipv4_addr; flags timeout; size 65536; }
    set autoban_v6 { type ipv6_addr; flags timeout; size 65536; }
$SUSPECT_SETS
$BLOCKLIST_SETS
$SCANNER_SETS
$FLEET_SETS
$NP_SETS

    # bogon/martian источники (RFC1918, CGNAT, loopback, link-local, TEST-NET, multicast)
    set bogon_v4 {
        type ipv4_addr; flags interval; auto-merge
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
            192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
            224.0.0.0/3
        }
    }

    # bogon-источники IPv6, которые НЕ могут легитимно прийти как saddr на WAN.
    # СОЗНАТЕЛЬНО без fe80::/10 (NDP/RA — link-local source) и без ff00::/8 (multicast):
    # их дроп убил бы соседство/автоконфиг IPv6. Только однозначно поддельные диапазоны.
    set bogon_v6 {
        type ipv6_addr; flags interval; auto-merge
        elements = {
            ::1/128, ::/128, ::ffff:0:0/96, 100::/64, 2001:db8::/32, fc00::/7
        }
    }

    # битые TCP-флаги / скан-пакеты → лог(rl) + drop
    chain scan_drop {
        limit rate 5/second log prefix "[na badflags] " level info
        counter drop
    }

$SYNPROXY_PRE

    chain input {
        type filter hook input priority filter; policy ${FW_POLICY};

        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # whitelist — всегда сверху (в т.ч. твой текущий SSH-IP)
        ip  saddr @whitelist_v4 accept
        ip6 saddr @whitelist_v6 accept
$FLEET_ACCEPT

        # уже забаненные
        ip  saddr @autoban_v4 drop
        ip6 saddr @autoban_v6 drop
$BLOCKLIST_DROP
$SCANNER_DROP

$ANTISPOOF

        # flag-drop: NULL, XMAS, SYN+FIN, SYN+RST, FIN+RST и прочие невалидные комбинации
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0                       jump scan_drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) jump scan_drop
        tcp flags & (fin|psh|urg) == (fin|psh|urg)                         jump scan_drop
        tcp flags & (syn|fin) == (syn|fin)                                 jump scan_drop
        tcp flags & (syn|rst) == (syn|rst)                                 jump scan_drop
        tcp flags & (fin|rst) == (fin|rst)                                 jump scan_drop
        tcp flags & (fin|ack) == fin                                       jump scan_drop
        tcp flags & (psh|ack) == psh                                       jump scan_drop
        tcp flags & (ack|urg) == urg                                       jump scan_drop

        # ICMP: пинг работает, флуд режется. Лимит PER-IP (meter), НЕ глобальный — иначе
        # нода с сотнями пингующих клиентов упирается в общий потолок и пинг «пропадает».
        ip protocol icmp icmp type echo-request meter icmp4 { ip saddr limit rate ${ICMP_RATE}/second burst ${ICMP_BURST} packets } accept
        ip protocol icmp icmp type echo-request drop
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        icmpv6 type echo-request meter icmp6 { ip6 saddr limit rate ${ICMP_RATE}/second burst ${ICMP_BURST} packets } accept
        icmpv6 type echo-request drop
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, time-exceeded, parameter-problem, destination-unreachable, mld-listener-query, mld-listener-report, mld-listener-done } accept

$SYNPROXY_IN

$SSH_RULES

        # сервисные TCP-порты (per-IP лимиты)
$TCP_RULES

        # сервисные UDP-порты (per-IP лимиты)
$UDP_RULES

$NODE_RULES

$PORTSCAN

        $FW_CATCHALL
    }

    chain forward { type filter hook forward priority filter; policy accept; }
    chain output  { type filter hook output  priority filter; policy accept; }
}
NFT

# ─── Проверка синтаксиса ДО применения ───────────────────────────────────────
if ! nft -c -f "$NFT_FILE"; then
    err "Сгенерированный ruleset не прошёл nft -c. Файл: $NFT_FILE (ничего не применено)."
    exit 1
fi
ok "nft -c: синтаксис валиден"

if [[ "$DRY_RUN" == "1" ]]; then
    ok "DRY-RUN: файл сгенерирован и проверен. Применение пропущено."
    info "Посмотреть: cat $NFT_FILE"
    exit 0
fi

# ─── Применяем (с сейфти-таймером) ───────────────────────────────────────────
arm_safety
nft -f "$NFT_FILE"
ok "nftables na_filter применён"
# новый руллсет применён → прошлое срабатывание сейфти больше не актуально
rm -f "$STATE_DIR/safety-fired.last" 2>/dev/null || true

# boot-persist через свой сервис (не трогаем /etc/nftables.conf и чужие таблицы)
cat > /etc/systemd/system/na-firewall.service <<EOF
[Unit]
Description=node-accelerator nftables (na_filter)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
$SP_MODPROBE
ExecStart=/usr/sbin/nft -f $NFT_FILE
ExecReload=/usr/sbin/nft -f $NFT_FILE

[Install]
WantedBy=multi-user.target
EOF
# nf_synproxy грузим на boot (на стоковых ядрах модульный; на XanMod встроен — no-op).
if [[ "$SYNPROXY_OK" == "1" ]]; then
    echo "nf_synproxy" > /etc/modules-load.d/na-synproxy.conf
else
    rm -f /etc/modules-load.d/na-synproxy.conf 2>/dev/null || true
fi
systemctl daemon-reload
systemctl enable na-firewall.service >/dev/null 2>&1 || true
systemctl enable nftables >/dev/null 2>&1 || true
ok "na-firewall.service включён (правила переживут reboot — если не сработает сейфти-таймер: он теперь снимает и автозагрузку)"

fi  # ═══ конец блока файрвола (FW_MODE=skip его пропускает) ═══

# ─── CrowdSec + firewall-bouncer ─────────────────────────────────────────────
if [[ "$ENABLE_CROWDSEC" == "1" ]]; then
    title "CrowdSec + nftables firewall-bouncer"
    if ! command -v cscli >/dev/null 2>&1; then
        info "Подключаю APT-репозиторий CrowdSec (пиннингованный ключ $CROWDSEC_FP)…"
        if setup_crowdsec_repo; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec >/dev/null 2>&1 || warn "crowdsec не установился"
        elif [[ "$CROWDSEC_STRICT" == "1" ]]; then
            warn "пиннингованный репо CrowdSec не поднялся, CROWDSEC_STRICT=1 → CrowdSec пропущен (curl|bash-фоллбэк запрещён)"
        else
            # last-resort: официальный установщик. -fsSL (а не -s): при HTTP-ошибке/
            # редиректе curl падает, а не отдаёт HTML в bash. Осознанный компромисс:
            # достаточно СДЕЛАТЬ packagecloud недостижимым (egress-фильтр/DNS), чтобы
            # сюда свалиться — кто параноит, ставит CROWDSEC_STRICT=1.
            warn "пиннингованный репо не поднялся — fallback на официальный установщик (curl|bash; отключается CROWDSEC_STRICT=1)"
            curl -fsSL https://install.crowdsec.net | bash >/dev/null 2>&1 || warn "install.crowdsec.net недоступен"
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec >/dev/null 2>&1 || warn "crowdsec не установился"
        fi
    fi
    if command -v cscli >/dev/null 2>&1; then
        systemctl enable --now crowdsec >/dev/null 2>&1 || true
        sleep 2
        cscli collections install crowdsecurity/sshd crowdsecurity/linux >/dev/null 2>&1 || true

        # whitelist админа/панели в самом CrowdSec — чтобы IPS их не банил.
        # Ключи ip:/cidr: пишем ТОЛЬКО при наличии записей (пустые ключи валят парсер).
        mkdir -p /etc/crowdsec/parsers/s02-enrich
        IP_ITEMS=""; CIDR_ITEMS=""
        for x in ${WHITELIST//,/ } ${ADMIN_IP:-}; do
            [[ -z "$x" ]] && continue
            if [[ "$x" == */* ]]; then CIDR_ITEMS+="    - \"$x\""$'\n'; else IP_ITEMS+="    - \"$x\""$'\n'; fi
        done
        if [[ -n "$IP_ITEMS$CIDR_ITEMS" ]]; then
            {
                echo "name: node-accelerator/whitelist"
                echo "description: never ban admin/panel"
                echo "whitelist:"
                echo "  reason: node-accelerator trusted"
                [[ -n "$IP_ITEMS"   ]] && { echo "  ip:";   printf "%s" "$IP_ITEMS"; }
                [[ -n "$CIDR_ITEMS" ]] && { echo "  cidr:"; printf "%s" "$CIDR_ITEMS"; }
            } > /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        else
            rm -f /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        fi

        # источник логов sshd через journald (на системах без /var/log/auth.log)
        mkdir -p /etc/crowdsec/acquis.d
        cat > /etc/crowdsec/acquis.d/na-sshd.yaml <<'ACQ'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
ACQ
        systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1 || true

        # firewall-bouncer (nftables-режим): своя таблица crowdsec/crowdsec6, priority -10
        if ! dpkg -s crowdsec-firewall-bouncer-nftables >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
                || warn "bouncer не установился"
        fi
        systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true

        # опциональный enroll в Console
        if [[ -n "${CROWDSEC_ENROLL_KEY:-}" ]]; then
            cscli console enroll "$CROWDSEC_ENROLL_KEY" >/dev/null 2>&1 \
                && { systemctl reload crowdsec >/dev/null 2>&1 || true; ok "enroll в CrowdSec Console отправлен"; } \
                || warn "enroll не прошёл (проверь ключ)"
        fi

        if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
            ok "CrowdSec + bouncer активны (community-блоклист + поведенческий бан)"
        else
            warn "CrowdSec/bouncer установлены, но сервис не active — проверь: cscli metrics"
        fi
    fi
else
    info "ENABLE_CROWDSEC=0 — CrowdSec пропущен"
fi

# ═══ v3.0 МОДУЛИ: fleet-sync · blocklists · ctguard ═══════════════════════════
# Зависимости только под включённые модули (jq — fleet/blocklists, conntrack — ctguard).
_dep_list=()
{ [[ "$FLEET_ON" == "1" ]] || [[ "$ENABLE_BLOCKLISTS" == "1" && "$FW_MODE" != "skip" ]] \
  || [[ "$ENABLE_SCANNERS" == "1" && "$FW_MODE" != "skip" ]]; } && _dep_list+=(jq)
# whois — только фолбэк для ASN-резолва (RIPEstat идёт по HTTPS и обычно достаточен)
[[ "$ENABLE_SCANNERS" == "1" && "$FW_MODE" != "skip" && "$SCANNER_ASN_SOURCE" != "ripestat" ]] && _dep_list+=(whois)
[[ "$ENABLE_CTGUARD" == "1" ]] && _dep_list+=(conntrack)
if [[ "${#_dep_list[@]}" -gt 0 ]]; then
    apt_install "${_dep_list[@]}" || warn "не доустановил зависимости: ${_dep_list[*]}"
fi

# ── Fleet auto-sync: ноды флота из Remnawave-панели → nft-сет na_fleet_* ──────
if [[ "$FLEET_ON" == "1" ]]; then
    title "Fleet auto-sync (ноды флота → whitelist)"
    if [[ -n "$REMNAWAVE_NODES_URL" ]] || [[ -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ]]; then
        umask 077; mkdir -p "$CONF_DIR"
        {
            [[ -z "$REMNAWAVE_URL"            ]] || printf 'REMNAWAVE_URL=%s\n' "$REMNAWAVE_URL"
            [[ -z "$REMNAWAVE_TOKEN"          ]] || printf 'REMNAWAVE_TOKEN=%s\n' "$REMNAWAVE_TOKEN"
            [[ -z "$REMNAWAVE_NODES_URL"      ]] || printf 'REMNAWAVE_NODES_URL=%s\n' "$REMNAWAVE_NODES_URL"
            [[ -z "$CADDY_AUTH_API_TOKEN"     ]] || printf 'CADDY_AUTH_API_TOKEN=%s\n' "$CADDY_AUTH_API_TOKEN"
        } > "$CONF_DIR/fleet.env"
        chmod 0600 "$CONF_DIR/fleet.env"; chown root:root "$CONF_DIR/fleet.env" 2>/dev/null || true
        if [[ -n "$REMNAWAVE_NODES_URL" ]]; then
            ok "источник нод сохранён в $CONF_DIR/fleet.env (NODES_URL — без API-токена на ноде)"
        else
            ok "токен панели сохранён в $CONF_DIR/fleet.env (root:root 0600, НЕ в protect.conf)"
        fi
    elif [[ -f "$CONF_DIR/fleet.env" ]]; then
        info "использую сохранённый $CONF_DIR/fleet.env"
    fi
    cat > /usr/local/sbin/na-fleet-sync <<'FSYNC'
#!/usr/bin/env bash
# na-fleet-sync — держит адреса нод флота в nft-сете na_fleet_v4/v6 (accept сразу
# после whitelist). Источник (из /etc/node-accelerator/fleet.env):
#   1) REMNAWAVE_NODES_URL — статический список БЕЗ токена панели на ноде: JSON того же
#      вида, что /api/nodes, ИЛИ plain-text «адрес на строку» (# — комментарий).
#   2) REMNAWAVE_URL + REMNAWAVE_TOKEN — GET /api/nodes по Bearer. Токен уходит ТОЛЬКО
#      на заданный оператором URL. CADDY_AUTH_API_TOKEN (опц.) → X-Api-Key для Caddy
#      Security / Tiny Auth перед панелью.
# Fail-safe: источник недоступен / кривой ответ / 0 валидных IP → текущий whitelist нод
# НЕ трогаем (last-known-good). Применение отдельной nft-транзакцией: битые данные не
# ломают na_filter. Успех отмечается в /var/lib/node-accelerator/fleet-sync.last —
# na-diagnose показывает возраст последнего синка (протухший токен виден, а не молчит).
set -u
TAG=na-fleet-sync
ENVF=/etc/node-accelerator/fleet.env
STAMP=/var/lib/node-accelerator/fleet-sync.last
[ -r "$ENVF" ] || { logger -t "$TAG" "нет $ENVF — выкл"; exit 0; }
# shellcheck disable=SC1090
. "$ENVF"
URL="${REMNAWAVE_URL:-}"; TOKEN="${REMNAWAVE_TOKEN:-}"; NURL="${REMNAWAVE_NODES_URL:-}"
CADDY="${CADDY_AUTH_API_TOKEN:-}"
{ [ -n "$NURL" ] || { [ -n "$URL" ] && [ -n "$TOKEN" ]; }; } || { logger -t "$TAG" "источник не задан — выкл"; exit 0; }
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1 || { logger -t "$TAG" "сет na_fleet нет (protect без fleet) — выкл"; exit 0; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# Секреты уходят в ФАЙЛ заголовков (внутри 0700-каталога), а не в argv: аргументы
# процесса видны всей системе через /proc/<pid>/cmdline на всё время запроса.
HDRF="$TMP/hdr"
: > "$HDRF"; chmod 600 "$HDRF"
[ -n "$CADDY" ] && printf 'X-Api-Key: %s\n' "$CADDY" >> "$HDRF"
# В journald пишем URL без userinfo: README сам предлагает закрывать статический список
# basic-auth'ом (https://user:pass@host/nodes.json), а лог читает кто угодно с доступом
# к journalctl — пароль там жил бы вечно и повторялся каждый тик синка.
redact_url() { printf '%s' "$1" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@#\1***@#'; }
# curl срезает Authorization на кросс-хост редиректе, но кастомный X-Api-Key — НЕТ:
# с -L токен Caddy утёк бы на хост-цель редиректа. При заданном токене редиректы НЕ
# следуем (оператор задаёт финальный https-URL сам). Без токена -L оставляем, но
# --proto-redir '=https' не даёт редиректу увести фетч списка нод на cleartext http.
FS_REDIR=(-L --max-redirs 3)
[ -n "$CADDY" ] && FS_REDIR=(--max-redirs 0)
if [ -n "$NURL" ]; then
    SRC="$NURL"
    CURL_HDR=()
    [ -s "$HDRF" ] && CURL_HDR=(-H @"$HDRF")
    HTTP="$(curl -fsS "${FS_REDIR[@]}" --proto-redir '=https' --max-time 15 -o "$TMP/r" -w '%{http_code}' \
            "${CURL_HDR[@]}" "$NURL" 2>/dev/null || true)"
else
    command -v jq >/dev/null 2>&1 || { logger -t "$TAG" "нет jq (нужен для /api/nodes)"; exit 1; }
    URL="${URL%/}"; SRC="$URL/api/nodes"
    printf 'Authorization: Bearer %s\n' "$TOKEN" >> "$HDRF"
    printf 'Accept: application/json\n' >> "$HDRF"
    HTTP="$(curl -fsS --max-time 15 -o "$TMP/r" -w '%{http_code}' \
            -H @"$HDRF" "$SRC" 2>/dev/null || true)"
fi
[ "$HTTP" = "200" ] && [ -s "$TMP/r" ] || { logger -t "$TAG" "источник недоступен (HTTP=$HTTP) — last-known-good"; exit 0; }
: > "$TMP/addr"
if command -v jq >/dev/null 2>&1; then
    jq -r '.. | objects | .address? // empty' "$TMP/r" 2>/dev/null | awk 'NF' >> "$TMP/addr" || true
fi
if [ ! -s "$TMP/addr" ] && [ -n "$NURL" ]; then
    # plain-text режим NODES_URL: адрес/hostname на строку (валидация/резолв ниже).
    # s/\r$//: CRLF-файлы (Windows/панель/CDN) иначе оставляют \r в токене → 0 валидных
    # адресов навсегда. head -n 200: кэп на случай, если по URL прилетела HTML-страница
    # логина — не делать сотни getent-резолвов мусора каждый тик.
    sed -E 's/\r$//; s/#.*$//' "$TMP/r" | awk 'NF{print $1}' | head -n 200 >> "$TMP/addr"
fi
sort -u -o "$TMP/addr" "$TMP/addr"
[ -s "$TMP/addr" ] || { logger -t "$TAG" "в ответе нет адресов — last-known-good"; exit 0; }
: > "$TMP/v4"; : > "$TMP/v6"
while IFS= read -r a; do
    [ -n "$a" ] || continue
    if printf '%s' "$a" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$a" >> "$TMP/v4"; continue; fi
    if printf '%s' "$a" | grep -qE '^[0-9a-fA-F:]+$' && printf '%s' "$a" | grep -q ':'; then echo "$a" >> "$TMP/v6"; continue; fi
    getent ahostsv4 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v4"
    getent ahostsv6 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v6"
done < "$TMP/addr"
V4="$(grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$TMP/v4" 2>/dev/null | sort -u | paste -sd, -)"
V6="$(grep -E '^[0-9a-fA-F:]+$' "$TMP/v6" 2>/dev/null | grep ':' | sort -u | paste -sd, -)"
[ -n "$V4" ] || [ -n "$V6" ] || { logger -t "$TAG" "0 валидных IP — last-known-good"; exit 0; }
{
    echo "flush set inet na_filter na_fleet_v4"
    [ -n "$V4" ] && echo "add element inet na_filter na_fleet_v4 { $V4 }"
    echo "flush set inet na_filter na_fleet_v6"
    [ -n "$V6" ] && echo "add element inet na_filter na_fleet_v6 { $V6 }"
} > "$TMP/upd.nft"
n4=$(printf '%s' "$V4" | tr ',' '\n' | grep -c . || true)
n6=$(printf '%s' "$V6" | tr ',' '\n' | grep -c . || true)
if nft -f "$TMP/upd.nft" 2>/dev/null; then
    mkdir -p /var/lib/node-accelerator && date +%s > "$STAMP"
    logger -t "$TAG" "whitelist нод обновлён: ${n4} v4 + ${n6} v6 (из $(redact_url "$SRC"))"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good сохранён"
fi
FSYNC
    chmod +x /usr/local/sbin/na-fleet-sync
    cat > /etc/systemd/system/na-fleet-sync.service <<'EOF'
[Unit]
Description=node-accelerator fleet whitelist sync (Remnawave /api/nodes)
After=na-firewall.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/na-fleet-sync
EOF
    cat > /etc/systemd/system/na-fleet-sync.timer <<EOF
[Unit]
Description=node-accelerator fleet sync timer
[Timer]
OnBootSec=60s
OnUnitActiveSec=$FLEET_SYNC_INTERVAL
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-fleet-sync.timer >/dev/null 2>&1 || true
    /usr/local/sbin/na-fleet-sync >/dev/null 2>&1 || true
    ok "fleet-sync включён (интервал $FLEET_SYNC_INTERVAL). Лог: journalctl -t na-fleet-sync"
fi

# ── Статич-блоклисты: Spamhaus DROP + FireHOL L1 [+ Tor] → nft-сет blocklist_* ─
# (при FW_MODE=skip сеты blocklist_* не существуют — модуль пропускается, info выше)
if [[ "$ENABLE_BLOCKLISTS" == "1" && "$FW_MODE" != "skip" ]]; then
    title "Статич-блоклисты (Spamhaus DROP / FireHOL L1$([[ "$BLOCK_TOR" == "1" ]] && echo ' / Tor'))"
    cat > /usr/local/sbin/na-blocklist-update <<'BLUP'
#!/usr/bin/env bash
# na-blocklist-update — обновляет nft-сеты blocklist_v4/v6 из публичных threat-фидов.
# Источники: Spamhaus DROP (json v4+v6), FireHOL Level 1 (v4), опц. Tor exit-list.
# Плюс /etc/node-accelerator/custom-blocklist.txt (локальные дополнения оператора).
# Bogon/private-фильтр, валидация, отдельная nft-транзакция (битый фид не ломает
# na_filter), last-known-good при недоступности фидов.
set -u
TAG=na-blocklist
BLOCK_TOR_FLAG="${1:-0}"
CUSTOM=/etc/node-accelerator/custom-blocklist.txt
nft list set inet na_filter blocklist_v4 >/dev/null 2>&1 || { logger -t "$TAG" "сет blocklist нет — выкл"; exit 0; }
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fetch() { curl -fsSL --connect-timeout 10 --max-time 60 "$1" 2>/dev/null; }
: > "$TMP/v4.raw"; : > "$TMP/v6.raw"
# Spamhaus DROP (json). jq может не быть — тогда фид пропускается.
if command -v jq >/dev/null 2>&1; then
    fetch https://www.spamhaus.org/drop/drop_v4.json | jq -r '.cidr // empty' 2>/dev/null >> "$TMP/v4.raw"
    fetch https://www.spamhaus.org/drop/drop_v6.json | jq -r '.cidr // empty' 2>/dev/null >> "$TMP/v6.raw"
fi
# FireHOL Level 1 (v4, high-confidence)
fetch https://iplists.firehol.org/files/firehol_level1.netset | grep -vE '^#' >> "$TMP/v4.raw"
# Tor exit nodes (опц.)
[ "$BLOCK_TOR_FLAG" = "1" ] && fetch https://check.torproject.org/torbulkexitlist >> "$TMP/v4.raw"
# локальные дополнения оператора (v4 и v6 вперемешку)
[ -r "$CUSTOM" ] && grep -vE '^\s*#|^\s*$' "$CUSTOM" >> "$TMP/v4.raw" && grep ':' "$CUSTOM" 2>/dev/null >> "$TMP/v6.raw"
# v4: только валидные IP/CIDR, без приватных/CGNAT/loopback/0.0.0.0
grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$TMP/v4.raw" 2>/dev/null \
  | grep -vE '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)' \
  | sort -u > "$TMP/v4.clean"
# v6: из jq-чистых .cidr (+ кастомные), базовая sanity
grep -hE '^[0-9a-fA-F:/]+$' "$TMP/v6.raw" 2>/dev/null | grep ':' | sort -u > "$TMP/v6.clean"
N4="$(grep -c . "$TMP/v4.clean" 2>/dev/null || echo 0)"
N6="$(grep -c . "$TMP/v6.clean" 2>/dev/null || echo 0)"
[ "$N4" -gt 0 ] || { logger -t "$TAG" "0 v4-записей (фиды недоступны?) — last-known-good"; exit 0; }
{
    echo "flush set inet na_filter blocklist_v4"
    echo "add element inet na_filter blocklist_v4 { $(paste -sd, "$TMP/v4.clean") }"
    if [ "$N6" -gt 0 ]; then
        echo "flush set inet na_filter blocklist_v6"
        echo "add element inet na_filter blocklist_v6 { $(paste -sd, "$TMP/v6.clean") }"
    fi
} > "$TMP/bl.nft"
if nft -f "$TMP/bl.nft" 2>/dev/null; then
    mkdir -p /var/lib/node-accelerator && date +%s > /var/lib/node-accelerator/blocklist.last
    logger -t "$TAG" "blocklist обновлён: ${N4} v4 + ${N6} v6"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good"
fi
BLUP
    chmod +x /usr/local/sbin/na-blocklist-update
    cat > /etc/systemd/system/na-blocklist.service <<EOF
[Unit]
Description=node-accelerator threat blocklist update
After=na-firewall.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/na-blocklist-update $BLOCK_TOR
EOF
    cat > /etc/systemd/system/na-blocklist.timer <<EOF
[Unit]
Description=node-accelerator blocklist refresh timer
[Timer]
OnBootSec=120s
OnUnitActiveSec=$BLOCKLIST_REFRESH
RandomizedDelaySec=300
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-blocklist.timer >/dev/null 2>&1 || true
    /usr/local/sbin/na-blocklist-update "$BLOCK_TOR" >/dev/null 2>&1 || true
    ok "блоклисты включены (обновление $BLOCKLIST_REFRESH). Лог: journalctl -t na-blocklist"
fi

# ── Масс-сканеры: ASN-лист (RIPEstat/whois) + префикс-фиды → сеты scanner_* ───
if [[ "$ENABLE_SCANNERS" == "1" && "$FW_MODE" != "skip" ]]; then
    title "Блок масс-сканеров (ASN + префикс-фиды)"
    if [[ ! -f "$CONF_DIR/scanner-asns.txt" ]]; then
        cat > "$CONF_DIR/scanner-asns.txt" <<'ASNS'
# node-accelerator: ASN организаций, чьё ЕДИНСТВЕННОЕ занятие — массовое сканирование
# и индексация интернета. Один ASN на строку, # — комментарий.
#
# КРИТЕРИЙ ВКЛЮЧЕНИЯ: весь трафик из AS является сканирующим. Хостинг/облако/CDN сюда
# НЕ ВНОСИТЬ, даже если оттуда прилетают сканы — сканеров внутри Linode, Azure, GCP,
# DigitalOcean режут ТОЛЬКО префикс-фиды (см. na-scanner-update). Блокировка облака
# целиком по ASN выносит десятки тысяч легитимных адресов вместе с парой сканеров.
#
# Предохранитель: ASN, отдавший больше SCANNER_ASN_MAX_PREFIXES префиксов, пропускается
# целиком с warn в лог — значит, он вырос в хостинг и его надо пересмотреть вручную.

# Число в скобках — сколько IPv4-префиксов AS анонсировала на момент составления
# списка. Растущее число = повод перепроверить, не превратилась ли контора в хостинг.

# — исследовательские сканеры полного интернета —
AS398324    # Censys, Inc. (ARIN-01)   (15)
AS398705    # Censys, Inc. (ARIN-02)   (2)
AS398722    # Censys, Inc. (ARIN-03)   (2)
AS211298    # Driftnet Ltd             (4)
AS213412    # ONYPHE SAS               (5)
AS208843    # Alpha Strike Labs GmbH   (2)
AS204428    # SS-Net / Stretchoid      (1)

# — мелкие сети, с которых идёт устойчивый брут/скан и ничего кроме —
AS202412    # Omegatech LTD            (21)
AS214940    # KPROHOST LLC             (2)
AS219502    # Storm Industries LLC     (1)
AS213790    # Limited Network LTD      (5)

# СОЗНАТЕЛЬНО НЕ ВКЛЮЧЕНЫ (проверено по RIPEstat) — оставлено как памятка, чтобы их
# не внесли повторно:
#   AS25369  Hydra Communications — 238 префиксов, это уже хостинг, а не сканер
#   AS209425 KOI Cloud Services   — облачный провайдер
#   AS396982 Google Cloud (3457), AS63949 Akamai/Linode, AS8075 Microsoft,
#   AS14061 DigitalOcean          — сканеры внутри них режутся ТОЛЬКО префикс-фидами
#   AS60068 CDN77, AS398101 GoDaddy, AS3214 xTom, AS200651 FlokiNET,
#   AS137409 GSL Networks         — хостинги; в наблюдаемых списках сканеров не значатся
ASNS
        chmod 0644 "$CONF_DIR/scanner-asns.txt"
        ok "создан $CONF_DIR/scanner-asns.txt (11 ASN). Правь его, а не скрипт."
    else
        info "$CONF_DIR/scanner-asns.txt уже есть — оставлен как есть."
    fi

    cat > /usr/local/sbin/na-scanner-update <<'SCUP'
#!/usr/bin/env bash
# na-scanner-update — наполняет nft-сеты scanner_v4/v6 сетями масс-сканеров.
#
# Два источника с разными областями применимости:
#   • ASN-лист ($ASN_FILE) — только чисто-сканерные организации. Префиксы берутся с
#     RIPEstat по HTTPS; whois RADB (TCP/43) — фолбэк, потому что часть хостеров режет
#     исходящий 43-й порт и whois там висит до таймаута.
#   • Префикс-фиды — сканеры внутри крупных облаков, которые по ASN резать нельзя.
#
# Три предохранителя, без которых такой блоклист опаснее атаки:
#   1. ASN_MAX_PREFIXES — ASN, разросшийся в хостинг, пропускается целиком.
#   2. MIN_PREFIXLEN — префикс короче /16 отбрасывается (защита от кривого фида).
#   3. protected-IP — префикс, накрывающий свой адрес, шлюз, панель, ноду флота или
#      whitelist, отбрасывается. Именно так блоклист не отрезает ноду от управления.
# Отдельная nft-транзакция: битый фид не роняет na_filter; при пустом результате
# остаётся last-known-good.
set -u
TAG=na-scanner
CONF=/etc/node-accelerator/protect.conf
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF" 2>/dev/null
ASN_FILE=/etc/node-accelerator/scanner-asns.txt
CUSTOM=/etc/node-accelerator/custom-scanners.txt
ASN_MAX_PREFIXES="${SCANNER_ASN_MAX_PREFIXES:-96}"
MIN_PREFIXLEN="${SCANNER_MIN_PREFIXLEN:-16}"
SRC="${SCANNER_ASN_SOURCE:-auto}"
FEEDS="${SCANNER_FEEDS:-1}"
RIPESTAT_TIMEOUT="${RIPESTAT_TIMEOUT:-15}"
WHOIS_TIMEOUT="${WHOIS_TIMEOUT:-20}"

nft list set inet na_filter scanner_v4 >/dev/null 2>&1 || { logger -t "$TAG" "сет scanner нет — выкл"; exit 0; }
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
: > "$TMP/v4.raw"; : > "$TMP/v6.raw"

# ── protected: то, что нельзя дропнуть ни при каких фидах ────────────────────
{
    ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'
    ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}'
    # элементы сета печатаются многострочно и по несколько в строке; берём всё, что
    # похоже на IPv4, начиная со строки elements =. Сет может отсутствовать — не ошибка.
    for s in whitelist_v4 na_fleet_v4 na_nodeport_wl_v4; do
        nft list set inet na_filter "$s" 2>/dev/null \
          | sed -n '/elements[[:space:]]*=/,$p' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
    done
} 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u > "$TMP/protected"
NPROT="$(grep -c . "$TMP/protected" 2>/dev/null || echo 0)"
# Пустой protected — это не «нечего защищать», а сломанный разбор. Без него блоклист
# может накрыть панель, и мы этого не заметим: лучше громко отказаться от обновления.
if [ "${NPROT:-0}" -lt 1 ]; then
    logger -t "$TAG" "protected-список пуст (свой адрес не определился?) — обновление ОТМЕНЕНО, last-known-good"
    exit 1
fi

ip2int() { local a b c d; IFS=. read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
# «накрывает ли CIDR хоть один protected-адрес» — только v4; v6 идёт без проверки,
# поэтому v6-префиксы принимаются лишь из ASN-резолва, не из произвольных фидов.
covers_protected() {
    local cidr="$1" net len m ni
    net="${cidr%/*}"; len="${cidr#*/}"; [ "$net" = "$cidr" ] && len=32
    [ "$len" -ge 0 ] 2>/dev/null || return 1
    if [ "$len" -eq 0 ]; then return 0; fi
    m=$(( (0xFFFFFFFF << (32 - len)) & 0xFFFFFFFF ))
    ni=$(( $(ip2int "$net") & m ))
    local p
    while read -r p; do
        [ -n "$p" ] || continue
        [ $(( $(ip2int "$p") & m )) -eq "$ni" ] && return 0
    done < "$TMP/protected"
    return 1
}

# ── ASN → префиксы ───────────────────────────────────────────────────────────
_ripestat_v4() {
    command -v jq >/dev/null 2>&1 || return 1
    curl -fsSL --max-time "$RIPESTAT_TIMEOUT" --retry 1 \
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=$1" 2>/dev/null \
      | jq -r '.data.prefixes[]?.prefix // empty' 2>/dev/null
}
_whois_v4() {
    command -v whois >/dev/null 2>&1 || return 1
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=5 "$WHOIS_TIMEOUT" whois -h whois.radb.net -- "-i origin $1" 2>/dev/null
    else
        whois -h whois.radb.net -- "-i origin $1" 2>/dev/null
    fi | awk '/^route:/{print $2}'
}

n_asn=0; n_skip=0
if [ -r "$ASN_FILE" ]; then
    while IFS= read -r line; do
        asn="${line%%#*}"; asn="$(printf '%s' "$asn" | tr -d '[:space:]')"
        [ -n "$asn" ] || continue
        case "$asn" in AS[0-9]*) ;; *) continue ;; esac
        pfx=""
        [ "$SRC" != "whois" ] && pfx="$(_ripestat_v4 "$asn")"
        if [ -z "$pfx" ] && [ "$SRC" != "ripestat" ]; then pfx="$(_whois_v4 "$asn")"; fi
        [ -n "$pfx" ] || { logger -t "$TAG" "$asn: префиксы не получены — пропуск"; continue; }
        cnt4="$(printf '%s\n' "$pfx" | grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$' || true)"
        if [ "${cnt4:-0}" -gt "$ASN_MAX_PREFIXES" ]; then
            logger -t "$TAG" "$asn: ${cnt4} префиксов > лимита ${ASN_MAX_PREFIXES} — ПРОПУЩЕН целиком (вырос в хостинг? пересмотри $ASN_FILE)"
            n_skip=$((n_skip+1)); continue
        fi
        printf '%s\n' "$pfx" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$' >> "$TMP/v4.raw"
        printf '%s\n' "$pfx" | grep -E '^[0-9a-fA-F:]+/[0-9]+$' >> "$TMP/v6.raw"
        n_asn=$((n_asn+1))
    done < "$ASN_FILE"
fi

# ── префикс-фиды (сканеры внутри крупных облаков) ────────────────────────────
# Внешние списки: содержимое подконтрольно их авторам, поэтому оно проходит ровно те
# же три предохранителя, что и ASN-резолв, и НЕ может накрыть панель/флот/свой адрес.
n_feed=0
if [ "$FEEDS" = "1" ]; then
    for u in \
        "https://raw.githubusercontent.com/sancliffe/gcp-drop-mass-scanners/main/live_data/blacklist-scanners.txt" \
        "https://raw.githubusercontent.com/cleverg0d/PublicGuard/main/scanners_list.txt" ; do
        got="$(curl -fsSL --connect-timeout 10 --max-time 60 "$u" 2>/dev/null | grep -vE '^\s*#|^\s*$')" || continue
        [ -n "$got" ] || continue
        printf '%s\n' "$got" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?$' >> "$TMP/v4.raw"
        n_feed=$((n_feed + $(printf '%s\n' "$got" | grep -c . || echo 0)))
    done
fi
[ -r "$CUSTOM" ] && grep -vE '^\s*#|^\s*$' "$CUSTOM" >> "$TMP/v4.raw"

# ── фильтрация ───────────────────────────────────────────────────────────────
n_wide=0; n_prot=0
: > "$TMP/v4.clean"
while read -r c; do
    [ -n "$c" ] || continue
    case "$c" in */*) len="${c#*/}" ;; *) c="$c/32"; len=32 ;; esac
    [ "$len" -ge "$MIN_PREFIXLEN" ] 2>/dev/null || { n_wide=$((n_wide+1)); continue; }
    case "$c" in 0.*|10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*) continue ;; esac
    if [ "$NPROT" -gt 0 ] && covers_protected "$c"; then
        logger -t "$TAG" "префикс $c накрывает свой/панельный/флотовый адрес — ОТБРОШЕН"
        n_prot=$((n_prot+1)); continue
    fi
    printf '%s\n' "$c" >> "$TMP/v4.clean"
done < <(sort -u "$TMP/v4.raw")
sort -u -o "$TMP/v4.clean" "$TMP/v4.clean"
grep -E '^[0-9a-fA-F:]+/[0-9]+$' "$TMP/v6.raw" 2>/dev/null | sort -u > "$TMP/v6.clean"

N4="$(grep -c . "$TMP/v4.clean" 2>/dev/null || echo 0)"
N6="$(grep -c . "$TMP/v6.clean" 2>/dev/null || echo 0)"
[ "$N4" -gt 0 ] || { logger -t "$TAG" "0 v4-записей (ASN=${n_asn}, фиды=${n_feed}) — last-known-good"; exit 0; }
{
    echo "flush set inet na_filter scanner_v4"
    echo "add element inet na_filter scanner_v4 { $(paste -sd, "$TMP/v4.clean") }"
    if [ "$N6" -gt 0 ]; then
        echo "flush set inet na_filter scanner_v6"
        echo "add element inet na_filter scanner_v6 { $(paste -sd, "$TMP/v6.clean") }"
    fi
} > "$TMP/sc.nft"
if nft -f "$TMP/sc.nft" 2>/dev/null; then
    mkdir -p /var/lib/node-accelerator && date +%s > /var/lib/node-accelerator/scanner.last
    # Кэш применённого набора. Сеты nft живут только в памяти ядра: после ребута
    # scanner_* пустые, а таймер придёт лишь через свой интервал — на живой ноде
    # это оказалось ~12 минут полностью без блоклиста. na-scanner-restore.service
    # заливает этот файл сразу после na-firewall, ещё до появления сети наружу.
    cp -f "$TMP/sc.nft" /var/lib/node-accelerator/scanner-cache.nft 2>/dev/null || true
    logger -t "$TAG" "scanner обновлён: ${N4} v4 + ${N6} v6 (ASN=${n_asn}, ASN-пропущено=${n_skip}, фид-строк=${n_feed}, широких=${n_wide}, защищённых=${n_prot})"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good"
fi
SCUP
    chmod +x /usr/local/sbin/na-scanner-update
    cat > /etc/systemd/system/na-scanner.service <<'EOF'
[Unit]
Description=node-accelerator mass-scanner blocklist update
After=na-firewall.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/na-scanner-update
EOF
    cat > /etc/systemd/system/na-scanner.timer <<EOF
[Unit]
Description=node-accelerator scanner blocklist refresh timer
[Timer]
OnBootSec=180s
OnUnitActiveSec=$SCANNER_REFRESH
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    # Восстановление сета при загрузке из кэша — без сети, мгновенно. Без него нода
    # после каждого ребута какое-то время стоит с пустым scanner_*: сеты nft не
    # переживают перезагрузку, а таймер приходит по своему расписанию (замерено на
    # живой ноде: ~12 минут открытого окна).
    cat > /etc/systemd/system/na-scanner-restore.service <<'EOF'
[Unit]
Description=node-accelerator: restore scanner blocklist from cache at boot
After=na-firewall.service nftables.service
Wants=na-firewall.service
ConditionPathExists=/var/lib/node-accelerator/scanner-cache.nft
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /var/lib/node-accelerator/scanner-cache.nft
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable na-scanner-restore.service >/dev/null 2>&1 || true
    systemctl enable --now na-scanner.timer >/dev/null 2>&1 || true
    # Наполняем сет и ПРОВЕРЯЕМ результат. Первый прогон может уйти впустую: если
    # na_filter перезагружается после него, сет обнуляется, а таймер вернётся только
    # через неделю — то есть защита молча не работает всё это время. Поэтому одна
    # повторная попытка, а если и она пустая — предупреждение, а не тихий успех.
    _sc_count() { nft -j list set inet na_filter scanner_v4 2>/dev/null \
        | jq '[.nftables[].set.elem[]?] | length' 2>/dev/null || echo 0; }
    /usr/local/sbin/na-scanner-update >/dev/null 2>&1 || true
    _sc4="$(_sc_count)"
    if [[ "${_sc4:-0}" -lt 1 ]]; then
        /usr/local/sbin/na-scanner-update >/dev/null 2>&1 || true
        _sc4="$(_sc_count)"
    fi
    if [[ "${_sc4:-0}" -lt 1 ]]; then
        warn "сет scanner_v4 пуст после двух попыток — фиды недоступны? Проверь: journalctl -t na-scanner; наполнить вручную: na-scanner-update"
    else
        ok "блок сканеров включён: ${_sc4} интервалов в scanner_v4 (обновление $SCANNER_REFRESH). Лог: journalctl -t na-scanner"
    fi
fi

# ── conntrack phantom-eviction (защита от distributed connect-and-hold) ───────
if [[ "$ENABLE_CTGUARD" == "1" ]]; then
    title "conntrack-guard (phantom-eviction)$([[ "$NA_CTG_ENFORCE" == "1" ]] && echo ' [ENFORCE]' || echo ' [observe]')"
    cat > "$CONF_DIR/ctguard.conf" <<EOF
# node-accelerator ctguard — детект distributed connect-and-hold по «живым» сокетам.
# Источник-фантом: conntrack ≫ живых сокетов (ss) → соединения брошены. CGNAT-safe:
# эвикт только концентрированный холдер с conntrack ≥ PHANTOM_MIN и live ≤ LIVE_FLOOR.
NA_CTG_ENFORCE=$NA_CTG_ENFORCE
NA_CTG_PHANTOM_MIN=${NA_CTG_PHANTOM_MIN:-4000}
NA_CTG_LIVE_FLOOR=${NA_CTG_LIVE_FLOOR:-2}
NA_CTG_BANTIME=${NA_CTG_BANTIME:-15m}
NA_CTG_COARSE_MULT=${NA_CTG_COARSE_MULT:-3}
EOF
    chmod 0640 "$CONF_DIR/ctguard.conf"
    cat > /usr/local/sbin/na-ctguard <<'CTG'
#!/usr/bin/env bash
# na-ctguard — liveness-aware защита от distributed connect-and-hold флуда. Класс атаки,
# который статичные rate-limit'ы не ловят: сотни IP открывают тысячи TCP, проходят
# handshake и БРОСАЮТ их — conntrack пухнет, приложение (xray) захлёбывается, но per-IP
# счётчики молчат (пик атаки пересекается с легит-CGNAT-потолком). Признак фантома:
# conntrack ≫ живых сокетов (ss). Дёшево: дорогой `conntrack -L` только если коарс-гейт
# (conntrack ≫ ss) сработал. CGNAT-safe: пропускаем источники с живыми сокетами,
# малым conntrack или в whitelist. observe-режим (NA_CTG_ENFORCE=0) — только лог.
set -u
TAG=na-ctguard
CONF=/etc/node-accelerator/ctguard.conf
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"
ENFORCE="${NA_CTG_ENFORCE:-0}"
PHANTOM_MIN="${NA_CTG_PHANTOM_MIN:-4000}"
LIVE_FLOOR="${NA_CTG_LIVE_FLOOR:-2}"
BANTIME="${NA_CTG_BANTIME:-15m}"
COARSE_MULT="${NA_CTG_COARSE_MULT:-3}"
command -v conntrack >/dev/null 2>&1 || { logger -t "$TAG" "нет conntrack-tools"; exit 0; }

# своя изолированная таблица (priority -5 → раньше na_filter); rollback = удалить таблицу
nft list table inet na_ctguard >/dev/null 2>&1 || nft -f - <<'NFTG'
table inet na_ctguard {
    set phantom_v4 { type ipv4_addr; flags timeout; size 131072; }
    set phantom_v6 { type ipv6_addr; flags timeout; size 131072; }
    chain input {
        type filter hook input priority -5; policy accept;
        ip  saddr @phantom_v4 drop
        ip6 saddr @phantom_v6 drop
    }
}
NFTG

CT_TOTAL="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
SS_TOTAL="$(ss -tnH state established 2>/dev/null | wc -l)"
# коарс-гейт: дорогой дамп только если conntrack заметно больше живых сокетов И велик
[ "$CT_TOTAL" -ge "$PHANTOM_MIN" ] || exit 0
[ "$CT_TOTAL" -ge $((SS_TOTAL * COARSE_MULT)) ] || exit 0

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# живые established по src-IP клиента
ss -tnH state established 2>/dev/null | awk '{print $NF}' \
  | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' | sort | uniq -c > "$TMP/live"
# conntrack по ПЕРВОМУ src= (это клиентский IP) — только tcp
conntrack -L -p tcp 2>/dev/null \
  | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/){print substr($i,5); break}}' \
  | sort | uniq -c | sort -rn > "$TMP/ct"

is_white() {  # в whitelist na_filter или в fleet-сете?
    local ip="$1" s4 s6
    if printf '%s' "$ip" | grep -q ':'; then s4=whitelist_v6; s6=na_fleet_v6; else s4=whitelist_v4; s6=na_fleet_v4; fi
    nft get element inet na_filter "$s4" "{ $ip }" >/dev/null 2>&1 && return 0
    nft get element inet na_filter "$s6" "{ $ip }" >/dev/null 2>&1 && return 0
    return 1
}
cand=0; eict=0
while read -r cnt ip; do
    [ -n "${ip:-}" ] || continue
    [ "$cnt" -ge "$PHANTOM_MIN" ] || break   # отсортировано по убыванию → дальше только меньше
    is_white "$ip" && continue
    live="$(awk -v ip="$ip" '$2==ip{print $1; f=1} END{if(!f)print 0}' "$TMP/live")"
    [ "${live:-0}" -le "$LIVE_FLOOR" ] || continue   # есть живые сокеты → легит/shared-front, щадим
    cand=$((cand+1))
    if [ "$ENFORCE" = "1" ]; then
        if printf '%s' "$ip" | grep -q ':'; then setn=phantom_v6; else setn=phantom_v4; fi
        nft add element inet na_ctguard "$setn" "{ $ip timeout $BANTIME }" 2>/dev/null \
            && conntrack -D -s "$ip" >/dev/null 2>&1 && eict=$((eict+1))
        logger -t "$TAG" "evict $ip ct=$cnt live=$live (bantime $BANTIME)"
    else
        logger -t "$TAG" "[observe] phantom-кандидат $ip ct=$cnt live=$live (NA_CTG_ENFORCE=0 — без эвикта)"
    fi
done < "$TMP/ct"
[ "$cand" -gt 0 ] && logger -t "$TAG" "тик: ct_total=$CT_TOTAL ss=$SS_TOTAL кандидатов=$cand эвиктов=$eict enforce=$ENFORCE"
exit 0
CTG
    chmod +x /usr/local/sbin/na-ctguard
    cat > /etc/systemd/system/na-ctguard.service <<'EOF'
[Unit]
Description=node-accelerator conntrack phantom-eviction
After=na-firewall.service
[Service]
Type=oneshot
# не отбираем CPU у xray под атакой
Nice=10
IOSchedulingClass=idle
ExecStart=/usr/local/sbin/na-ctguard
EOF
    cat > /etc/systemd/system/na-ctguard.timer <<EOF
[Unit]
Description=node-accelerator ctguard timer
[Timer]
OnBootSec=90s
OnUnitActiveSec=${NA_CTG_INTERVAL:-20s}
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-ctguard.timer >/dev/null 2>&1 || true
    if [[ "$NA_CTG_ENFORCE" == "1" ]]; then
        ok "ctguard ENFORCE: фантом-холдеры эвиктятся. Лог: journalctl -t na-ctguard"
    else
        warn "ctguard в OBSERVE (только лог). Убедись по journalctl -t na-ctguard, что кандидаты = только атакеры (live≤$NA_CTG_LIVE_FLOOR), затем NA_CTG_ENFORCE=1 + ре-ран protect."
    fi
fi

# ─── fw-status хелпер ────────────────────────────────────────────────────────
cat > /usr/local/sbin/na-fw-status <<'STAT'
#!/usr/bin/env bash
# Panic — первым и громко: это временный режим, который режет и легитимных
# клиентов. Забытый включённым panic выглядит как «сервис тормозит без причины».
if nft list table inet na_panic >/dev/null 2>&1; then
    echo "⚠⚠  PANIC-РЕЖИМ АКТИВЕН — лимиты ужесточены, часть легитимных клиентов режется"
    echo "    $(cat /var/lib/node-accelerator/panic.on 2>/dev/null)"
    echo "    Снять: na-fw-panic off"
    echo
fi
echo "── nft table inet na_filter ──"
nft list table inet na_filter 2>/dev/null | grep -E 'policy|counter|elements' | head -40
echo
echo "── autoban (живые баны) ──"
echo "v4: $(nft list set inet na_filter autoban_v4 2>/dev/null | grep -oE '[0-9.]+ timeout' | wc -l)   v6: $(nft list set inet na_filter autoban_v6 2>/dev/null | grep -c timeout)"
nft list set inet na_filter autoban_v4 2>/dev/null | grep -oE '[0-9.]+ (timeout|expires)[^,]*' | head -15
if nft list set inet na_filter suspect_v4 >/dev/null 2>&1; then
    echo "suspect (наблюдение, ban-once) v4: $(nft list set inet na_filter suspect_v4 2>/dev/null | grep -c timeout)   v6: $(nft list set inet na_filter suspect_v6 2>/dev/null | grep -c timeout)"
fi
echo
if nft list set inet na_filter blocklist_v4 >/dev/null 2>&1; then
    echo "── threat-блоклисты ──"
    echo "v4: $(nft list set inet na_filter blocklist_v4 2>/dev/null | grep -coE '[0-9.]+')   v6: $(nft list set inet na_filter blocklist_v6 2>/dev/null | grep -c ':')   (обновляет na-blocklist-update)"
    echo
fi
if nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1; then
    echo "── fleet-sync (ноды флота → whitelist) ──"
    echo "v4: $(nft list set inet na_filter na_fleet_v4 2>/dev/null | grep -coE '[0-9.]+')   v6: $(nft list set inet na_filter na_fleet_v6 2>/dev/null | grep -c ':')   (последний синк: $(journalctl -t na-fleet-sync -n1 --no-pager -o cat 2>/dev/null | head -c 80))"
    echo
fi
if nft list table inet na_ctguard >/dev/null 2>&1; then
    echo "── ctguard (phantom-eviction) ──"
    enf="$(awk -F= '/^NA_CTG_ENFORCE/{print $2}' /etc/node-accelerator/ctguard.conf 2>/dev/null)"
    echo "режим: $([ "${enf:-0}" = 1 ] && echo ENFORCE || echo observe)   фантомов в блоке v4: $(nft list set inet na_ctguard phantom_v4 2>/dev/null | grep -c timeout)   v6: $(nft list set inet na_ctguard phantom_v6 2>/dev/null | grep -c timeout)"
    journalctl -t na-ctguard -n3 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
    echo
fi
if [ -f /var/lib/node-accelerator/.synproxy-degraded ]; then
    echo "⚠ SYNPROXY DEGRADED: $(cat /var/lib/node-accelerator/.synproxy-degraded)"
    echo
fi
if command -v cscli >/dev/null 2>&1; then
    echo "── CrowdSec ──"
    cscli decisions list 2>/dev/null | head -20
    echo
    cscli metrics 2>/dev/null | sed -n '1,25p'
fi
STAT
chmod +x /usr/local/sbin/na-fw-status

# ─── top-talkers хелпер ──────────────────────────────────────────────────────
# Если нода за реверс-прокси/балансировщиком/CDN — трафик идёт с горстки upstream-IP,
# и per-IP лимиты их режут. Хелпер показывает топ источников → кандидаты в WHITELIST=.
cat > /usr/local/sbin/na-fw-top-talkers <<'TT'
#!/usr/bin/env bash
# Топ удалённых IP по числу установленных TCP-соединений на сервисных портах.
# Если нода за реверс-прокси/балансировщиком/CDN — легитимный трафик приходит с
# небольшого набора upstream-адресов; их стоит занести в WHITELIST=, чтобы per-IP
# лимиты (CONN_LIMIT/SYN_RATE) их не резали. Хелпер показывает кандидатов.
#   na-fw-top-talkers [порт[,порт...]] [N]   (по умолчанию порты из protect, N=25)
set -u
DEF=443
if [ -r /var/lib/node-accelerator/protect.installed ]; then
    DEF="$(awk -F= '/^tcp_ports=/{print $2}' /var/lib/node-accelerator/protect.installed)"
fi
PORTS="${1:-${DEF:-443}}"
N="${2:-25}"
filt=""
for p in ${PORTS//,/ }; do
    [ -n "$p" ] || continue
    filt="${filt:+$filt or }sport = :$p"
done
[ -n "$filt" ] || { echo "нет портов для анализа"; exit 1; }
echo "── Топ-$N удалённых IP по established TCP на портах: $PORTS ──"
ss -Hnt state established "( $filt )" 2>/dev/null \
    | awk '{print $5}' \
    | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' \
    | sort | uniq -c | sort -rn | head -n "$N"
TT
chmod +x /usr/local/sbin/na-fw-top-talkers

# ─── panic-режим ─────────────────────────────────────────────────────────────
# Под живой атакой «поправить protect.conf и ре-ранить protect.sh» — плохой план:
# это минуты работы, и na_filter.nft начинается с `delete table inet na_filter`,
# то есть пересборка ОБНУЛЯЕТ autoban/suspect/блоклисты/fleet ровно в тот момент,
# когда они нужнее всего (сеты nft живут только в памяти ядра).
# Поэтому panic — ОТДЕЛЬНАЯ таблица inet na_panic с приоритетом -3: после
# crowdsec (-10) и ctguard (-5), но перед na_filter (0). Она только режет NEW
# сверх ужесточённого потолка и снимается одной командой; na_filter не трогается.
cat > /usr/local/sbin/na-fw-panic <<'PANIC'
#!/usr/bin/env bash
# na-fw-panic on [--mult=N] | off | status
#
# Аварийное ужесточение per-IP лимитов в N раз (по умолчанию 4) поверх обычной
# защиты. Отдельная таблица inet na_panic — na_filter (баны, блоклисты, счётчики)
# остаётся нетронутой, снятие мгновенное.
#
# ⚠️ ВАЖНО: panic бьёт и по легитимным клиентам. Он помогает, когда флуд идёт с
# горстки IP, и НЕ помогает, когда он размазан по сотням адресов по чуть-чуть —
# там per-IP лимиты бессильны by design. Сначала `na-diagnose --attack`.
set -u
CONF=/etc/node-accelerator/protect.conf
STATE=/var/lib/node-accelerator
MARK="$STATE/panic.on"
MULT=4

die() { echo "na-fw-panic: $*" >&2; exit 1; }

for a in "$@"; do
    case "$a" in
        --mult=*) MULT="${a#*=}" ;;
    esac
done
case "$MULT" in ''|*[!0-9]*) die "--mult должен быть целым числом" ;; esac
[ "$MULT" -ge 2 ] || die "--mult меньше 2 не имеет смысла"

# Делим лимит, но не ниже 1: 0/second означало бы «дропать всё».
d() { local v=$(( ${1:-4} / MULT )); [ "$v" -lt 1 ] && v=1; echo "$v"; }

# Элементы whitelist берём из ЖИВОГО na_filter, а не из protect.conf: там уже
# лежит транзитный IP текущей SSH-сессии, добавленный при установке. Читать
# конфиг значило бы запереть себя же при первом panic on.
# [^}]* вместо .* принципиально: sed жадный, и `\(.*\)}` захватывал бы всё до
# ПОСЛЕДНЕЙ скобки в дампе, утаскивая закрывающие скобки самого set/table.
wl_elements() {
    nft list set inet na_filter "$1" 2>/dev/null | tr '\t\n' '  ' \
        | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' | tr -s ' ' | sed 's/^ *//; s/ *$//'
}

panic_status() {
    if nft list table inet na_panic >/dev/null 2>&1; then
        echo "PANIC АКТИВЕН$([ -r "$MARK" ] && echo " — $(cat "$MARK")")"
        echo
        nft list table inet na_panic 2>/dev/null | grep -E 'counter packets [1-9]|dport' | head -30
        echo
        echo "Снять: na-fw-panic off"
    else
        echo "panic выключен (обычные лимиты)"
        [ -r "$MARK" ] && rm -f "$MARK"
    fi
}

panic_off() {
    nft list table inet na_panic >/dev/null 2>&1 || { echo "panic и так выключен"; exit 0; }
    nft delete table inet na_panic || die "не смог удалить таблицу na_panic"
    rm -f "$MARK"
    echo "panic снят — вернулись к обычным лимитам na_filter"
}

panic_on() {
    [ -r "$CONF" ] || die "нет $CONF — protect.sh здесь не запускался"
    # shellcheck disable=SC1090
    . "$CONF"
    : "${TCP_PORTS:=}" "${UDP_PORTS:=}" "${UDP_BULK_PORTS:=}" "${SSH_PORT:=22}" "${NODE_PORT:=}"
    : "${SYN_RATE:=60}" "${SYN_BURST:=120}" "${UDP_RATE:=200}" "${UDP_BURST:=400}"
    : "${UDP_BULK_RATE:=50000}" "${UDP_BULK_BURST:=100000}" "${CONN_LIMIT:=2048}"

    local sr sb ur ub br bb cl rules="" p
    sr=$(d "$SYN_RATE");        sb=$(d "$SYN_BURST")
    ur=$(d "$UDP_RATE");        ub=$(d "$UDP_BURST")
    br=$(d "$UDP_BULK_RATE");   bb=$(d "$UDP_BULK_BURST")
    cl=$(d "$CONN_LIMIT")

    for p in ${TCP_PORTS//,/ }; do
        [ -n "$p" ] || continue
        # SSH и node-port из panic исключены намеренно: у SSH своя connect-flood
        # защита в na_filter, а срезанный node-port — это отвал панели от ноды
        # посреди атаки. Ужесточать имеет смысл клиентские порты.
        # SSH_PORT/NODE_PORT могут быть списками ("22,2222") — сравнение целиком
        # их бы не исключило, поэтому ищем порт как элемент списка.
        case ",${SSH_PORT}," in *",${p},"*) continue ;; esac
        case ",${NODE_PORT}," in *",${p},"*) continue ;; esac
        rules="$rules
        tcp dport ${p} ct state new meter pt4_${p} { ip  saddr limit rate over ${sr}/second burst ${sb} packets } jump pdrop
        tcp dport ${p} ct state new meter pt6_${p} { ip6 saddr limit rate over ${sr}/second burst ${sb} packets } jump pdrop
        tcp dport ${p} ct state new meter pc4_${p} { ip  saddr ct count over ${cl} } jump pdrop
        tcp dport ${p} ct state new meter pc6_${p} { ip6 saddr ct count over ${cl} } jump pdrop"
    done

    for p in ${UDP_PORTS//,/ }; do
        [ -n "$p" ] || continue
        local r="$ur" b="$ub"
        case ",${UDP_BULK_PORTS}," in *",${p},"*) r="$br"; b="$bb" ;; esac
        rules="$rules
        udp dport ${p} meter pu4_${p} { ip  saddr limit rate over ${r}/second burst ${b} packets } jump pdrop
        udp dport ${p} meter pu6_${p} { ip6 saddr limit rate over ${r}/second burst ${b} packets } jump pdrop"
    done

    [ -n "$rules" ] || die "в protect.conf нет портов, которые имеет смысл ужесточать"

    local e4 e6 wl4="" wl6=""
    e4="$(wl_elements whitelist_v4)"; e6="$(wl_elements whitelist_v6)"
    [ -n "$e4" ] && wl4="elements = { $e4 }"
    [ -n "$e6" ] && wl6="elements = { $e6 }"

    local tmp; tmp="$(mktemp /tmp/na-panic.XXXXXX.nft)" || die "mktemp"
    cat > "$tmp" <<NFT
table inet na_panic {}
delete table inet na_panic

table inet na_panic {
    set pwl4 { type ipv4_addr; flags interval; auto-merge; $wl4 }
    set pwl6 { type ipv6_addr; flags interval; auto-merge; $wl6 }

    # Один общий chain на дроп: если бы log/counter/drop были тремя отдельными
    # правилами с одинаковым meter, лимит пересчитывался бы на каждом и по факту
    # оказался бы втрое строже заданного.
    chain pdrop {
        limit rate 5/second burst 10 packets log prefix "[na panic] " level warn
        counter drop
    }

    chain input {
        type filter hook input priority -3; policy accept;

        # Живые сессии не трогаем — panic режет только НОВЫЕ подключения.
        # Иначе ужесточение обрывало бы уже работающих клиентов, а не атакующих.
        ct state established,related accept
        ip  saddr @pwl4 accept
        ip6 saddr @pwl6 accept
$rules
    }
}
NFT
    if ! nft -c -f "$tmp"; then
        echo "na-fw-panic: сгенерированный ruleset не прошёл проверку. Файл: $tmp" >&2
        exit 1
    fi
    nft -f "$tmp" || die "не смог применить na_panic"
    rm -f "$tmp"

    mkdir -p "$STATE"
    echo "mult=${MULT} since=$(date -Is) syn=${sr}/s conn=${cl} udp=${ur}/s" > "$MARK"
    echo "PANIC ВКЛЮЧЁН (×${MULT} строже): syn ${SYN_RATE}→${sr}/s, conn ${CONN_LIMIT}→${cl}, udp ${UDP_RATE}→${ur}/s"
    echo "SSH (${SSH_PORT}) и node-port (${NODE_PORT:-—}) не ужесточались."
    echo
    echo "Смотреть срабатывания: na-fw-logs -f --panic"
    echo "Снять:                 na-fw-panic off"
}

case "${1:-status}" in
    on)     panic_on ;;
    off)    panic_off ;;
    status) panic_status ;;
    *) echo "usage: na-fw-panic on [--mult=N] | off | status" >&2; exit 1 ;;
esac
PANIC
chmod +x /usr/local/sbin/na-fw-panic

# ─── просмотр срабатываний файрвола ──────────────────────────────────────────
# Правила пишут в kernel log с префиксами [na synflood]/[na portscan]/
# [na ssh-flood]/[na badflags]/[na panic]. Под атакой смотреть их голым
# journalctl -k неудобно: нужен фильтр по IP или порту, а поля лежат внутри
# строки (SRC=..., DPT=...), не в journald-полях.
cat > /usr/local/sbin/na-fw-logs <<'FWLOG'
#!/usr/bin/env bash
# na-fw-logs [-f] [--lines=N] [--ip=IP] [--port=PORT] [--kind=synflood|portscan|ssh-flood|badflags|panic]
#            [--panic] [--top]
#
# Читает срабатывания правил na_filter/na_panic из kernel log.
# --top — не поток строк, а сводка «топ источников» за выбранное окно.
set -u
LINES=200; FOLLOW=0; IP=""; PORT=""; KIND=""; TOP=0

for a in "$@"; do
    case "$a" in
        -f|--follow) FOLLOW=1 ;;
        --lines=*)   LINES="${a#*=}" ;;
        --ip=*)      IP="${a#*=}" ;;
        --port=*)    PORT="${a#*=}" ;;
        --kind=*)    KIND="${a#*=}" ;;
        --panic)     KIND="panic" ;;
        --top)       TOP=1 ;;
        -h|--help)   sed -n '2,9p' "$0"; exit 0 ;;
        *) echo "na-fw-logs: неизвестный аргумент: $a" >&2; exit 1 ;;
    esac
done

# Логирование могло быть не включено вовсе — тогда пустой вывод собьёт с толку.
if ! nft list table inet na_filter 2>/dev/null | grep -q 'log prefix "\[na '; then
    echo "⚠ в na_filter нет log-правил — срабатывания в kernel log не пишутся." >&2
    echo "  Счётчики дропов при этом видны: na-fw-status" >&2
fi

PAT="\[na ${KIND:-[a-z-]*}\]"
src() {
    if [ "$FOLLOW" = 1 ]; then
        journalctl -k -f -n "$LINES" -o cat 2>/dev/null
    else
        journalctl -k -n 20000 --no-pager -o cat 2>/dev/null
    fi
}

filter() {
    grep -E --line-buffered "$PAT" \
      | { [ -n "$IP" ]   && grep -E --line-buffered "SRC=${IP//./\\.}[ =]" || cat; } \
      | { [ -n "$PORT" ] && grep -E --line-buffered "DPT=${PORT}[ =]" || cat; }
}

if [ "$TOP" = 1 ]; then
    [ "$FOLLOW" = 1 ] && { echo "na-fw-logs: --top и -f несовместимы" >&2; exit 1; }
    echo "── Топ источников по срабатываниям ${KIND:+($KIND) }──"
    src | filter | grep -oE 'SRC=[0-9a-fA-F.:]+' | sed 's/^SRC=//' \
        | sort | uniq -c | sort -rn | head -25
    echo
    echo "── По типам правил ──"
    src | filter | grep -oE '\[na [a-z-]+\]' | sort | uniq -c | sort -rn
    exit 0
fi

if [ "$FOLLOW" = 1 ]; then
    src | filter
else
    src | filter | tail -n "$LINES"
fi
FWLOG
chmod +x /usr/local/sbin/na-fw-logs

# ─── Маркер ──────────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
cat > "$STATE_DIR/protect.installed" <<EOF
installed_at=$(date -Is)
na_version=$NA_VERSION
backup=$BACKUP
fw_mode=$FW_MODE
ssh_port=$SSH_EFF
tcp_ports=$TCP_PORTS
udp_ports=$UDP_PORTS
node_port=$NP_EFF
crowdsec=$ENABLE_CROWDSEC
nft_file=${NFT_FILE:-}
EOF

# Персист эффективного конфига → ре-ран без ENV сохранит эти значения (ENV всё ещё
# переопределяет). WHITELIST хранит только заданный оператором список (без транзитного
# авто-IP текущей SSH-сессии — тот добавляется в WL4/WL6 отдельно).
# REMNAWAVE_URL/TOKEN сюда НЕ пишем — токен живёт в fleet.env (0600), fleet-режим
# восстанавливается по наличию fleet.env.
save_conf "$CONF_DIR/protect.conf" \
    FW_MODE SSH_PORT TCP_PORTS UDP_PORTS NODE_PORT WHITELIST \
    SYN_RATE SYN_BURST UDP_RATE UDP_BURST UDP_BULK_PORTS UDP_BULK_RATE UDP_BULK_BURST CONN_LIMIT \
    ICMP_RATE ICMP_BURST SSH_RATE SSH_BURST SSH_BAN_TIME \
    PORTSCAN_BAN_TIME PORTSCAN_RATE PORTSCAN_BURST \
    ENABLE_PORTSCAN_BAN ENABLE_CROWDSEC CROWDSEC_STRICT ENABLE_SYNPROXY \
    ENABLE_BLOCKLISTS BLOCK_TOR BLOCKLIST_REFRESH ENABLE_BANONCE SUSPECT_TIME \
    ENABLE_SCANNERS SCANNER_REFRESH SCANNER_ASN_SOURCE SCANNER_ASN_MAX_PREFIXES \
    SCANNER_MIN_PREFIXLEN SCANNER_FEEDS RIPESTAT_TIMEOUT WHOIS_TIMEOUT \
    FLEET_SYNC FLEET_SYNC_INTERVAL \
    NODE_PORT_WHITELIST_ONLY NODE_PORT_LAST NODE_PORT_AUTOWL NODE_PORT_PEERS SAFETY_DELAY \
    ENABLE_CTGUARD NA_CTG_ENFORCE NA_CTG_PHANTOM_MIN NA_CTG_LIVE_FLOOR \
    NA_CTG_COARSE_MULT NA_CTG_BANTIME NA_CTG_INTERVAL

# ─── Подтверждение работы ────────────────────────────────────────────────────
if [[ "$FW_MODE" == "skip" ]]; then
    # nftables не ставился — сейфти-таймер не взводился, самоблокировка невозможна.
    echo
    ok "Готово. Файрвол не ставился (FW_MODE=skip). Решишь закрыть порты — инструкция выше, либо ре-ран с FW_MODE=strict. Статус CrowdSec: na-fw-status"
else
    title "Подтверждение (защита от самоблокировки)"
    echo "  Открой НОВОЕ окно и проверь: ssh root@<этот сервер>"
    echo "  (твой текущий IP $ADMIN_IP уже в whitelist, но лучше убедиться.)"
    echo
    if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]]; then
        read -r -p "Соединение работает? [y/N]: " c
        if [[ "$c" =~ ^[yYдД] ]]; then
            disarm_safety; ok "Сейфти-таймер снят. Защита активна."
        else
            warn "Сейфти оставлен: через ${SAFETY_DELAY}s na_filter удалится сам."
            warn "Если всё ок — сними: systemctl stop na-fw-safety.timer  (или kill из /tmp/na-fw-safety.pid)"
        fi
    else
        warn "Неинтерактивно: сейфти-таймер на ${SAFETY_DELAY}s АКТИВЕН."
        warn "Подтверди доступ и сними: systemctl stop na-fw-safety.timer"
    fi
    echo
    [[ "$FW_MODE" == "open" ]] && info "FW_MODE=open: не перечисленные порты открыты. Появится полный список — закрой всё ре-раном с FW_MODE=strict TCP_PORTS=… UDP_PORTS=…"
    ok "Готово. Статус: na-fw-status | топ источников (для WHITELIST за CDN/LB): na-fw-top-talkers"
    info "Под атакой: na-diagnose --attack (форма атаки) → na-fw-panic on (×4 строже) → na-fw-panic off"
    info "Срабатывания правил: na-fw-logs -f [--ip=X] [--port=N] | сводка: na-fw-logs --top"
fi
