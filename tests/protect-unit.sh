#!/usr/bin/env bash
#
# protect-unit.sh — юнит-тесты кусков protect.sh, которые до этого нигде не исполнялись:
# сгенерированный хелпер `na-fw-status`, разбор WHITELIST и сборка анти-скан-правил.
# Все три блока правились по аудиту боевого флота v4.0.1:
#
#   1. na-fw-status (issue #32/#36): счётчики наборов считались `grep -c timeout` по
#      выводу nft, где строка `flags dynamic,timeout` есть ВСЕГДА → пустой набор давал
#      «1», непустой был завышен, а na-fw-status и na-diagnose расходились между собой.
#      Здесь хелпер РЕАЛЬНО исполняется против стаба nft, который печатает наборы так же,
#      как nft 1.0.9/1.1.x — пустой динамический, непустой, многострочный, v6.
#   2. add_wl (issue #38): дубликат из CSV оператора уезжал в ruleset/CrowdSec как есть,
#      а /24 и шире принимались молча — при том, что whitelist в na это полный обход
#      защиты. Проверяем дедуп, нормализацию /32 и /128, предупреждение о широком CIDR.
#   3. анти-скан-лог (issue #35): рейт лога вынесен в PORTSCAN_LOG_RATE (в МИНУТУ),
#      0 = не логировать вовсе; плюс оценка суточного объёма против капа journald.
#   6. fw_busy_check (28.09.2026): применение ждёт не только свой protect.lock — узел
#      не правится, пока его держит fleet-fw-apply (оркестратор vpn) или взведена
#      чужая страховка; под оркестратором (FWA_UNIT) его блокировка — не помеха.
#   7. PORTSCAN_SKIP_PORTS (28.09.2026): правила бана анти-скана не считают клиентские
#      порты, лог-правило считает все; без ручки — как в апстриме; мусор — отказ.
#   9. SSH_NET_RATE и OBS_NET_PORTS (29.09.2026): /24-метры syn4net_22 и obs4net
#      генерирует шаблон — на своих местах в цепочке, с именами, по которым их сверяет
#      vpn; без ручек — как в апстриме; мусор — отказ; ре-ран без ENV их не снимает.
#
# Не требует root/сети/nft/systemd. Запуск: bash tests/protect-unit.sh
# Проверить на старой версии:  NA_PROTECT_SH=<путь> bash tests/protect-unit.sh  (упадёт)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTECT="${NA_PROTECT_SH:-$REPO_ROOT/scripts/protect.sh}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/etc" "$T/sbin"

# хелперам и protect.sh нужен bash ≥ 4.2 ([[ -v ]]) — на macOS системный древний
pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4"; exit 1; }

PASS=0; FAIL=0
check() { # check "описание" <ожидание> <факт>
    if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"
    else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi
}
checkf() { # checkf "описание" — фиксируем провал без сравнения
    FAIL=$((FAIL+1)); echo "  FAIL $1"
}

# ─── 1. Сгенерированный na-fw-status ─────────────────────────────────────────
echo "== 1. na-fw-status: счётчики наборов (issue #32/#36) =="

# Генератор хелпера — функция write_fw_status в protect.sh: вытаскиваем её целиком и
# исполняем с подсунутым lib/common.sh (оттуда declare -f вшивает nft_set_count).
awk '/^write_fw_status\(\) \{$/{f=1} f{print} f&&/^\}$/{exit}' "$PROTECT" > "$T/gen-fw-status.raw"
if [[ ! -s "$T/gen-fw-status.raw" ]]; then
    checkf "не нашёл генератор write_fw_status в $PROTECT (старая версия писала хелпер сырым heredoc'ом — счётчики там по grep -c)"
else
    sed -e "s#/usr/local/sbin/#$T/sbin/#g" "$T/gen-fw-status.raw" > "$T/gen-fw-status.sh"

    # стаб nft: печатает наборы ровно так, как настоящий nft 1.0.9/1.1.x
    cat > "$T/bin/nft" <<'NFT'
#!/usr/bin/env bash
# nft list table <family> <table>   |   nft list set <family> <table> <set>
if [[ "${1:-}" == "list" && "${2:-}" == "table" ]]; then
    case "${4:-}" in
        na_filter)  printf 'table inet na_filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n'; exit 0;;
        na_ctguard) exit 0;;
        *) exit 1;;
    esac
fi
[[ "${1:-}" == "list" && "${2:-}" == "set" ]] || exit 1
hdr() { printf 'table inet %s {\n\tset %s {\n\t\ttype %s\n\t\tsize 65536\n\t\tflags dynamic,timeout\n' "$3" "$1" "$2"; }
case "${5:-}" in
    autoban_v4)
        hdr autoban_v4 ipv4_addr na_filter
        printf '\t\telements = { 203.0.113.10 timeout 1d expires 1h11m50s608ms,\n\t\t\t     198.51.100.22 timeout 1d expires 55m }\n\t}\n}\n';;
    autoban_v6|suspect_v4|suspect_v6|phantom_v4)
        # ПУСТОЙ динамический набор: заголовок со словом timeout есть, элементов нет
        printf 'table inet t {\n\tset %s {\n\t\ttype addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\ttimeout 30m\n\t}\n}\n' "${5}";;
    phantom_v6)
        printf 'table inet na_ctguard {\n\tset phantom_v6 {\n\t\ttype ipv6_addr\n\t\tflags dynamic,timeout\n\t\telements = { 2001:db8::66 timeout 15m expires 12m3s }\n\t}\n}\n';;
    blocklist_v4)
        printf 'table inet na_filter {\n\tset blocklist_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 203.0.113.0/24, 198.51.100.0/24,\n\t\t\t     192.0.2.0/24 }\n\t}\n}\n';;
    blocklist_v6)
        printf 'table inet na_filter {\n\tset blocklist_v6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t}\n}\n';;
    na_fleet_v4)
        printf 'table inet na_filter {\n\tset na_fleet_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 203.0.113.5, 203.0.113.6 }\n\t}\n}\n';;
    na_fleet_v6)
        printf 'table inet na_filter {\n\tset na_fleet_v6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 2001:db8::5 }\n\t}\n}\n';;
    *) echo "Error: No such file or directory" >&2; exit 1;;
esac
NFT
    printf '#!/bin/sh\nexit 0\n' > "$T/bin/journalctl"
    chmod +x "$T/bin/nft" "$T/bin/journalctl"

    "$WBASH" -c "set -euo pipefail; . '$REPO_ROOT/scripts/lib/common.sh'; . '$T/gen-fw-status.sh'; write_fw_status" >/dev/null
    if [[ ! -x "$T/sbin/na-fw-status" ]]; then
        checkf "генератор не создал $T/sbin/na-fw-status"
    else
        check "тело nft_set_count вшито в хелпер (lib/common.sh рядом с ним не лежит)" \
              1 "$(grep -c '^nft_set_count ' "$T/sbin/na-fw-status")"
        OUT="$(PATH="$T/bin:$PATH" "$WBASH" "$T/sbin/na-fw-status" 2>&1)"
        check "autoban: 2 элемента v4 и ПУСТОЙ v6 (не «1» из-за flags dynamic,timeout)" \
              "v4: 2   v6: 0" "$(printf '%s\n' "$OUT" | sed -n 's/^\(v4: [0-9]*   v6: [0-9]*\)$/\1/p' | head -1)"
        check "suspect: оба набора пусты" \
              "suspect (наблюдение, ban-once) v4: 0   v6: 0" \
              "$(printf '%s\n' "$OUT" | grep -o 'suspect (наблюдение, ban-once) v4: [0-9]*   v6: [0-9]*')"
        check "blocklist: 3 интервала v4, пусто v6" "v4: 3   v6: 0" \
              "$(printf '%s\n' "$OUT" | grep -o 'v4: [0-9]*   v6: [0-9]*   (обновляет na-blocklist-update)' | sed 's/   (обновляет.*//')"
        check "fleet: 2 v4 + 1 v6" "v4: 2   v6: 1" \
              "$(printf '%s\n' "$OUT" | grep -o 'v4: [0-9]*   v6: [0-9]*   (последний синк' | sed 's/   (последний.*//')"
        check "ctguard: пусто v4, 1 фантом v6" "фантомов в блоке v4: 0   v6: 1" \
              "$(printf '%s\n' "$OUT" | grep -o 'фантомов в блоке v4: [0-9]*   v6: [0-9]*')"
        check "показаны сами баны (адрес + expires), а не только число" 2 \
              "$(printf '%s\n' "$OUT" | grep -c -E '^(203\.0\.113\.10|198\.51\.100\.22) timeout 1d expires')"
        check "строки заголовка набора в список банов не попадают" 0 \
              "$(printf '%s\n' "$OUT" | grep -c 'flags dynamic')"
    fi
fi

# ─── 2. add_wl: дедуп, нормализация, широкий CIDR ────────────────────────────
echo "== 2. WHITELIST: дедуп / нормализация / широкий CIDR (issue #38) =="
awk '/^WL4=""; WL6=""$/{f=1} /^add_wl "\$WHITELIST"/{f=0} f' "$PROTECT" > "$T/wl.sh"
if [[ ! -s "$T/wl.sh" ]]; then
    checkf "не смог извлечь блок разбора WHITELIST из $PROTECT"
else
    wl() { "$WBASH" -c "set -euo pipefail; . '$REPO_ROOT/scripts/lib/common.sh'; . '$T/wl.sh'; $1" 2>&1; }
    check "дубль в CSV → один элемент" "203.0.113.7" \
          "$(wl 'add_wl "203.0.113.7,203.0.113.7" >/dev/null; printf "%s" "$WL4"')"
    check "дубль замечен вслух (protect.conf не переписываем — чинит оператор)" 1 \
          "$(wl 'add_wl "203.0.113.7,203.0.113.7" | grep -c "указан дважды"')"
    check "о тройном повторе предупреждаем один раз, не простынёй" 1 \
          "$(wl 'add_wl "203.0.113.7,203.0.113.7,203.0.113.7" | grep -c "указан дважды"')"
    check "/32 и голый адрес — одно и то же значение" "203.0.113.7" \
          "$(wl 'add_wl "203.0.113.7/32,203.0.113.7" >/dev/null; printf "%s" "$WL4"')"
    check "/32 нормализован даже без дубля" "198.51.100.5" \
          "$(wl 'add_wl "198.51.100.5/32" >/dev/null; printf "%s" "$WL4"')"
    check "/128 нормализован, дубль по v6 ловится" "2001:db8::1" \
          "$(wl 'add_wl "2001:db8::1/128,2001:db8::1" >/dev/null; printf "%s" "$WL6"')"
    check "широкий v4 (/24) → warn про полный обход защиты" 1 \
          "$(wl 'add_wl "203.0.113.0/24" | grep -c "ПОЛНЫЙ обход защиты"')"
    check "в warn названо число адресов (2^8)" 1 \
          "$(wl 'add_wl "203.0.113.0/24" | grep -c "2\^8 адресов (256)"')"
    check "широкий v6 (/48) → warn" 1 \
          "$(wl 'add_wl "2001:db8:abc::/48" | grep -c "2\^80 адресов"')"
    check "/29 (порог) — молча" 0 \
          "$(wl 'add_wl "203.0.113.8/29" | grep -c "ПОЛНЫЙ обход"')"
    check "/64 v6 (порог) — молча" 0 \
          "$(wl 'add_wl "2001:db8:abc::/64" | grep -c "ПОЛНЫЙ обход"')"
    check "хост-адрес — молча" 0 \
          "$(wl 'add_wl "203.0.113.7,2001:db8::1" | grep -c "ПОЛНЫЙ обход\|дважды"')"
    check "auto-источник (IP текущей SSH-сессии) дублем не шумит" 0 \
          "$(wl 'add_wl "203.0.113.7" >/dev/null; add_wl "203.0.113.7" auto | grep -c "дважды"')"
    check "…и вторым элементом в набор не лезет" "203.0.113.7" \
          "$(wl 'add_wl "203.0.113.7" >/dev/null; add_wl "203.0.113.7" auto >/dev/null; printf "%s" "$WL4"')"
    check "мусор по-прежнему отвергается (rc=1)" "rc=1" \
          "$(wl 'add_wl "203.0.113.7; nft flush ruleset" >/dev/null 2>&1 || echo rc=1')"
    check "разделитель набора остаётся ', ' (формат elements = { … })" "203.0.113.7, 198.51.100.5" \
          "$(wl 'add_wl "203.0.113.7,198.51.100.5" >/dev/null; printf "%s" "$WL4"')"
fi

# ─── 3. Сборка анти-скан-правил: PORTSCAN_LOG_RATE ───────────────────────────
echo "== 3. анти-скан: рейт лога вынесен в ручку (issue #35) =="
awk '/^PORTSCAN=""$/{f=1} f{print} f&&/^fi$/{exit}' "$PROTECT" > "$T/portscan.sh"
if [[ ! -s "$T/portscan.sh" ]]; then
    checkf "не смог извлечь сборку PORTSCAN из $PROTECT"
else
    ps_run() {   # ps_run "<переопределения через ;>"
        "$WBASH" -c "set -euo pipefail
ENABLE_PORTSCAN_BAN=1; FW_MODE=strict; ENABLE_BANONCE=1
PORTSCAN_RATE=15; PORTSCAN_BURST=30; PORTSCAN_BAN_TIME=1h; SUSPECT_TIME=30m
PORTSCAN_LOG_RATE=60; PORTSCAN_LOG_BURST=30
$1
. '$T/portscan.sh'
printf '%s\n' \"\$PORTSCAN\"" 2>&1
    }
    check "дефолт v4.1: лог 60/минуту с burst 30" 1 \
          "$(ps_run ':' | grep -c 'limit rate 60/minute burst 30 packets log prefix "\[na portscan\] "')"
    check "прежние 5/second из правила ушли" 0 "$(ps_run ':' | grep -c '5/second log prefix "\[na portscan\]')"
    check "ручки доезжают до правила" 1 \
          "$(ps_run 'PORTSCAN_LOG_RATE=5; PORTSCAN_LOG_BURST=7' | grep -c 'limit rate 5/minute burst 7 packets')"
    check "PORTSCAN_LOG_RATE=0 → лог-правила нет вовсе" 0 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c '\[na portscan\]')"
    check "…но бан продолжает работать (meter → @autoban)" 1 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c 'add @autoban_v4')"
    check "…и наблюдение ban-once тоже (meter → @suspect)" 1 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c 'add @suspect_v4 { ip saddr timeout 30m }')"
    check "в ruleset остаётся видно, ПОЧЕМУ лога нет" 1 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c 'PORTSCAN_LOG_RATE=0')"
    check "без ban-once правило лога такое же" 1 \
          "$(ps_run 'ENABLE_BANONCE=0' | grep -c 'limit rate 60/minute burst 30 packets log prefix "\[na portscan\] "')"
fi

# ─── 4. Бюджет журнала под лог анти-скана ────────────────────────────────────
echo "== 4. бюджет journald под [na portscan] (issue #35) =="
awk '/^NA_JOURNAL_LINE_BYTES=/{f=1} /^check_journal_budget$/{exit} f' "$PROTECT" > "$T/budget.raw"
if [[ ! -s "$T/budget.raw" ]]; then
    checkf "в $PROTECT нет оценки бюджета журнала (check_journal_budget)"
else
    sed -e "s#/etc/systemd/journald.conf#$T/etc/journald.conf#g" "$T/budget.raw" > "$T/budget.sh"
    mkdir -p "$T/etc/journald.conf.d"
    bud() {   # bud "<переопределения>" — окружение как у боевого прогона
        "$WBASH" -c "set -euo pipefail; . '$REPO_ROOT/scripts/lib/common.sh'; . '$T/budget.sh'
ENABLE_PORTSCAN_BAN=1; FW_MODE=strict; PORTSCAN_LOG_RATE=60
$1" 2>&1
    }
    printf '[Journal]\nSystemMaxUse=300M\nSystemKeepFree=500M\n' > "$T/etc/journald.conf.d/na-size.conf"
    check "кап 300M из drop-in optimize распознан" 314572800 "$(bud 'journald_cap_bytes')"
    check "дефолтный рейт 60/мин при капе 300M — тишина" "" "$(bud 'check_journal_budget')"
    check "300/мин (прежние 5/сек) при том же капе → warn" 1 \
          "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget' | grep -c 'лог анти-скана')"
    check "…в warn названы оба числа: суточный объём и кап" 1 \
          "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget' | grep -c 'МБ/сутки при капе journald 300 МБ')"
    check "…и сказано, что делать" 1 \
          "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget' | grep -c 'снизь PORTSCAN_LOG_RATE')"
    check "PORTSCAN_LOG_RATE=0 → считать нечего" "" "$(bud 'PORTSCAN_LOG_RATE=0; check_journal_budget')"
    check "автобан за скан выключен → бюджет не при чём" "" \
          "$(bud 'ENABLE_PORTSCAN_BAN=0; PORTSCAN_LOG_RATE=300; check_journal_budget')"
    check "FW_MODE=open (анти-скан не ставится) → тишина" "" \
          "$(bud 'FW_MODE=open; PORTSCAN_LOG_RATE=300; check_journal_budget')"
    printf '[Journal]\nSystemMaxUse=2G\n' > "$T/etc/journald.conf.d/na-size.conf"
    check "суффикс G разбирается" 2147483648 "$(bud 'journald_cap_bytes')"
    check "большой кап — 300/мин уже не проблема" "" "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget')"
    printf '[Journal]\nSystemMaxUse=64M\n' > "$T/etc/journald.conf.d/na-size.conf"
    check "маленький кап — предупреждаем даже на дефолтном рейте" 1 \
          "$(bud 'check_journal_budget' | grep -c 'лог анти-скана')"
    # drop-in перебивает основной конфиг (порядок чтения systemd)
    printf '[Journal]\nSystemMaxUse=1G\n' > "$T/etc/journald.conf"
    check "drop-in побеждает journald.conf" 67108864 "$(bud 'journald_cap_bytes')"
    rm -f "$T/etc/journald.conf.d/na-size.conf"
    check "без drop-in берётся journald.conf" 1073741824 "$(bud 'journald_cap_bytes')"
    printf '[Journal]\n#SystemMaxUse=4G\n' > "$T/etc/journald.conf"
    check "закомментированный кап игнорируется → дефолт 300M" 314572800 "$(bud 'journald_cap_bytes')"
    rm -f "$T/etc/journald.conf"
    check "конфига нет вовсе → дефолт 300M (столько ставит optimize)" 314572800 "$(bud 'journald_cap_bytes')"
fi

# ─── 5. Полный apply: дедуп доезжает до всех мест разом ──────────────────────
# Три места хранят whitelist: nft-сет (через na_filter.nft), CrowdSec-парсер и
# protect.conf. Первые два дедупим, третий обязан сохранить список оператора дословно.
echo "== 5. apply: whitelist в ruleset / CrowdSec-yaml / protect.conf (issue #38) =="
A="$T/apply"
mkdir -p "$A/bin" "$A/sys" "$A/sbin" "$A/modload" "$A/conf" "$A/state" "$A/backup" "$A/crowdsec"
cp -r "$REPO_ROOT/scripts" "$A/scripts"
cp "$PROTECT" "$A/scripts/protect.sh"
sed -e "s#/etc/systemd/system/#$A/sys/#g" -e "s#/usr/local/sbin/#$A/sbin/#g" \
    -e "s#/etc/modules-load.d/#$A/modload/#g" -e "s#/etc/crowdsec#$A/crowdsec#g" \
    "$A/scripts/protect.sh" > "$A/p.tmp" && mv "$A/p.tmp" "$A/scripts/protect.sh"
# ip — стаб и здесь: на маке его нет, и сборка OUTPUT_RULES роняла apply с кодом 127
for c in systemctl modprobe nft systemd-run sysctl conntrack cscli sleep ip; do
    printf '#!/bin/sh\nexit 0\n' > "$A/bin/$c"; chmod +x "$A/bin/$c"
done
for c in curl docker ss dpkg apt-get; do
    printf '#!/bin/sh\nexit 1\n' > "$A/bin/$c"; chmod +x "$A/bin/$c"
done
cat >> "$A/scripts/lib/common.sh" <<STUB
require_root(){ :; }
detect_os(){ OS_ID=debian; OS_VER=12; OS_CODENAME=bookworm; }
default_iface(){ echo eth0; }
detect_ssh_port(){ echo 22; }
ssh_client_ip(){ echo "203.0.113.9"; }
apt_install(){ :; }
backup_dir(){ echo "$A/backup"; }
CONF_DIR="$A/conf"
STATE_DIR="$A/state"
STUB
DUPWL='198.51.100.4,203.0.113.7,198.51.100.4,203.0.113.7/32,203.0.113.0/24'
set +e
PATH="$A/bin:$PATH" WHITELIST="$DUPWL" ENABLE_CROWDSEC=1 NA_FWA_LOCK="$A/state/fleet-fw-apply.lock" \
    REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 "$WBASH" "$A/scripts/protect.sh" >"$A/apply.log" 2>&1
rc=$?
set -e
check "apply отработал (exit 0)" 0 "$rc"
check "unbound-переменных нет" 0 "$(grep -ciE 'unbound variable|bad substitution' "$A/apply.log")"
NFTF="$A/conf/na_filter.nft"
check "в ruleset адрес ровно один раз" 1 \
      "$(grep -o '198\.51\.100\.4' "$NFTF" | wc -l | tr -d ' ')"
check "…и нормализованный /32 не задвоил второй" 1 \
      "$(grep -o '203\.0\.113\.7\b' "$NFTF" | wc -l | tr -d ' ')"
check "авто-whitelist SSH-IP на месте" 1 "$(grep -c '203\.0\.113\.9' "$NFTF")"
YAML="$A/crowdsec/parsers/s02-enrich/na-whitelist.yaml"
if [[ ! -f "$YAML" ]]; then
    checkf "CrowdSec-whitelist не сгенерирован ($YAML)"
else
    check "в CrowdSec-yaml адрес один раз (а не как в CSV оператора)" 1 \
          "$(grep -c '"198\.51\.100\.4"' "$YAML")"
    check "…/32 нормализован в ip:, а не в cidr:" 1 "$(grep -c '"203\.0\.113\.7"' "$YAML")"
    check "…широкий /24 остался как cidr (оператор так решил, мы лишь предупредили)" 1 \
          "$(grep -c '"203\.0\.113\.0/24"' "$YAML")"
    check "…SSH-IP тоже в CrowdSec-whitelist" 1 "$(grep -c '"203\.0\.113\.9"' "$YAML")"
fi
check "protect.conf хранит WHITELIST дословно (это intent оператора)" 1 \
      "$(grep -c "WHITELIST:=$DUPWL}" "$A/conf/protect.conf")"
check "новые ручки персистятся" "60 30" \
      "$(grep -oE '^: "\$\{PORTSCAN_LOG_(RATE|BURST):=[0-9]+\}"$' "$A/conf/protect.conf" | grep -oE '[0-9]+' | paste -sd' ' -)"
check "дубли названы поимённо (оба, включая нормализованный /32)" 2 \
      "$(grep -c 'указан дважды' "$A/apply.log")"
check "широкий /24 предупреждён" 1 "$(grep -c 'ПОЛНЫЙ обход защиты' "$A/apply.log")"
check "хелпер na-fw-status собран со вшитым счётчиком" 1 \
      "$(grep -c '^nft_set_count ' "$A/sbin/na-fw-status")"

# ─── 6. Правка фаервола узла — одна за раз с оркестратором vpn ───────────────
# fleet-fw-apply.sh (vpn) держит /run/lock/fleet-fw-apply.lock и взводит
# fw-apply-safety-*, subnet-meter-rollout.sh — fw-safety, host-ssh-harden.sh —
# ssh-harden-rollback. protect.sh мимо них получал их откат поверх себя, а его
# na-fw-safety сносил их правку (vpn, остаток ревью Codex W, 28.09.2026). Под
# оркестратором (FWA_UNIT) его блокировка и страховка не чужие.
echo "== 6. fw_busy_check: блокировка fleet-fw-apply и чужие страховки =="
awk '/^NA_FWA_LOCK=/{f=1} f{print} f&&/^\}$/{exit}' "$PROTECT" > "$T/fwbusy.sh"
if ! grep -q '^fw_busy_check()' "$T/fwbusy.sh"; then
    checkf "нет fw_busy_check в $PROTECT — фаервол правится мимо блокировки fleet-fw-apply и чужих страховок"
else
    F="$T/fwb"
    mkdir -p "$F/bin" "$F/run"
    # systemctl list-units … ШАБЛОН… — юниты из $FWB_UNITS, совпавшие с шаблоном
    cat > "$F/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == list-units ]] || exit 0
[[ -n "${FWB_SYSTEMCTL_FAIL:-}" ]] && exit 1      # D-Bus недоступен: ни строки, код 1
shift; pats=""
for a in "$@"; do [[ "$a" == --* ]] || pats="$pats $a"; done
while IFS= read -r n; do
    for p in $pats; do
        # shellcheck disable=SC2053 # сравнение с шаблоном юнитов — намеренно
        [[ $n == $p ]] && { echo "$n loaded active waiting stub"; break; }
    done
done < "$FWB_UNITS"
exit 0    # как настоящий systemctl: ничего не совпало — пустой вывод и код 0
STUB
    # flock -n FD — настоящий flock(2) на унаследованном дескрипторе, как у util-linux
    cat > "$F/bin/flock" <<'STUB'
#!/usr/bin/perl
use strict; use warnings; use Fcntl qw(:flock);
my $nb = 0;
while (@ARGV && $ARGV[0] =~ /^-/) { $nb = 1 if shift(@ARGV) eq '-n'; }
open(my $fh, '>&=', shift @ARGV) or die "flock-стаб: $!\n";
exit(flock($fh, LOCK_EX | ($nb ? LOCK_NB : 0)) ? 0 : 1);
STUB
    chmod +x "$F/bin/systemctl" "$F/bin/flock"
    LOCKF="$F/run/fleet-fw-apply.lock"
    fwb() {   # fwb "юнит…" [ПЕРЕМЕННАЯ=значение…] → «ok» или текст отказа
        printf '%s\n' $1 > "$F/units"; shift
        env PATH="$F/bin:$PATH" FWB_UNITS="$F/units" NA_FWA_LOCK="$LOCKF" "$@" \
            "$WBASH" -c "set -euo pipefail; err(){ echo \"\$*\"; }; . '$T/fwbusy.sh'; fw_busy_check; echo ok" 2>&1 \
            | tail -1 || true
    }
    hold()    { exec 7>"$LOCKF"; PATH="$F/bin:$PATH" flock -n 7; }
    release() { exec 7>&-; }
    FWA=fw-apply-safety-20260928-120000-a1b2c3
    check "узел свободен — ok" ok "$(fwb '')"
    check "своя na-fw-safety прошлого прогона не мешает (arm_safety перевзведёт)" ok "$(fwb 'na-fw-safety.timer')"
    hold
    check "блокировку держит fleet-fw-apply — отказ" 1 "$(fwb '' | grep -c 'узел занят: идёт fleet-fw-apply')"
    check "под оркестратором (FWA_UNIT) его блокировка и страховка — не помеха" ok \
          "$(fwb "$FWA.timer" FWA_UNIT="$FWA")"
    check "NA_NO_LOCK=1 — без проверки" ok "$(fwb 'fw-safety.timer' NA_NO_LOCK=1)"
    release
    check "взведена fw-apply-safety-* без FWA_UNIT — отказ" 1 \
          "$(fwb "$FWA.timer" | grep -c "чужая страховка: $FWA.timer —")"
    check "под оркестратором fw-safety всё равно чужая — отказ с её именем" 1 \
          "$(fwb "$FWA.timer fw-safety.timer" FWA_UNIT="$FWA" | grep -c 'чужая страховка: fw-safety.timer —')"
    check "взведена ssh-harden-rollback — отказ" 1 \
          "$(fwb 'ssh-harden-rollback.timer' | grep -c 'чужая страховка: ssh-harden-rollback.timer')"
    check "проверка стоит перед взводом na-fw-safety, до nft -f" 1 \
          "$(grep -A1 '^fw_busy_check$' "$PROTECT" | grep -c '^arm_safety$')"
    # ревью Codex N2 (29.09): упавший systemctl давал пустой список — применение шло;
    # таймер отработал, а его откат (.service) ещё идёт — проверка его не видела
    check "systemctl list-units отказал — отказ, а не «свободно»" 1 \
          "$(fwb '' FWB_SYSTEMCTL_FAIL=1 | grep -c 'не смог проверить чужие страховки')"
    check "идёт откат fw-safety.service — отказ" 1 \
          "$(fwb 'fw-safety.service' | grep -c 'чужая страховка: fw-safety.service')"
    check "идёт откат ssh-harden-rollback.service — отказ" 1 \
          "$(fwb 'ssh-harden-rollback.service' | grep -c 'чужая страховка: ssh-harden-rollback.service')"
    check "nohup-страховка закрывает обе блокировки (fd 8 и protect.lock на fd 9)" 1 \
          "$(grep -c '2>&1 8>&- 9>&- &$' "$PROTECT")"
fi

# ─── 8. Хелпер na-scanner-update: оборванный whois (ревью Codex N2, 29.09) ─────
# _whois_v4 отдавал код awk: whois, оборванный timeout после первых строк, возвращал
# огрызок как полный список, и тот перезаписывал исправный кэш ASN.
echo "== 8. na-scanner-update: оборванный whois — отказ, а не огрызок =="
awk '/^_whois_v4\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$PROTECT" > "$T/whois.sh"
if ! grep -q '^_whois_v4()' "$T/whois.sh"; then
    checkf "нет _whois_v4 в $PROTECT"
else
    W="$T/wh"; mkdir -p "$W/bin"
    printf '#!/bin/sh\nprintf "route: 198.51.100.0/24\\nroute: 203.0.113.0/24\\n"\n' > "$W/bin/whois"
    # timeout: команда отработала, код — из WH_RC (124 — не уложился и убит)
    printf '#!/bin/sh\nwhile [ "${1#-}" != "$1" ]; do shift; done\nshift\n"$@"\nexit "${WH_RC:-0}"\n' > "$W/bin/timeout"
    chmod +x "$W/bin/whois" "$W/bin/timeout"
    wh() { env PATH="$W/bin:$PATH" WH_RC="$1" WHOIS_TIMEOUT=5 "$WBASH" -c ". '$T/whois.sh'; _whois_v4 AS64500; echo rc=\$?" 2>&1 | paste -sd' ' -; }
    check "whois уложился — оба префикса" "198.51.100.0/24 203.0.113.0/24 rc=0" "$(wh 0)"
    check "whois оборван timeout (124) — ничего и код ≠ 0" "rc=1" "$(wh 124)"
fi

# ─── 7. PORTSCAN_SKIP_PORTS: анти-скан не считает клиентские порты ───────────
# Порог 15 новых SYN в минуту ловил активных XHTTP-клиентов на 443/8444 и банил их на
# час вместе с UDP; флот чинил гвард после каждого ре-рана скриптом node-baseline (vpn),
# и минуты между ре-раном и правкой клиенты были под баном (28.09.2026). Генерация —
# DRY_RUN копии из раздела 5; `ip` — стаб (маршрута по умолчанию на стенде нет).
echo "== 7. PORTSCAN_SKIP_PORTS: исключение клиентских портов в правилах гварда =="
gen() {   # gen [ПЕРЕМЕННАЯ=значение…] → путь сгенерированного na_filter или «нет файла» и вывод
    local out f
    out=$(env PATH="$A/bin:$PATH" REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=1 FW_MODE=strict ENABLE_CROWDSEC=0 "$@" \
          "$WBASH" "$A/scripts/protect.sh" 2>&1) || true
    f=$(printf '%s\n' "$out" | sed -n 's/.*Посмотреть: cat //p' | tail -1)
    if [[ -n "$f" && -f "$f" ]]; then echo "$f"; else echo "нет файла"; printf '%s\n' "$out" | tail -3; fi
}
SKIP='tcp dport != { 443, 8444, 2222 }'
f=$(gen PORTSCAN_SKIP_PORTS=443,8444,2222 | head -1)
if [[ ! -f "$f" ]]; then
    checkf "DRY_RUN с PORTSCAN_SKIP_PORTS не дал файла: $(gen PORTSCAN_SKIP_PORTS=443,8444,2222 | tail -2)"
else
    check "ban-once: исключение во всех четырёх правилах гварда (psc4, psc6, ps4, ps6)" 4 \
          "$(grep -E '(meter |add @)(ps4|psc4|ps6|psc6) ' "$f" | grep -cF "ct state new $SKIP ")"
    check "лог-правило анти-скана считает все порты — исключения в нём нет" 0 \
          "$(grep -F '[na portscan]' "$f" | grep -c 'dport !=')"
    rm -f "$f"
fi
f=$(gen | head -1)
if [[ -f "$f" ]]; then
    check "без ручки — как в апстриме: четыре правила гварда без исключения" "4 0" \
          "$(grep -cE '(meter |add @)(ps4|psc4|ps6|psc6) ' "$f") $(grep -c 'dport != { 443' "$f")"
    rm -f "$f"
else
    checkf "DRY_RUN без ручки не дал файла"
fi
f=$(gen PORTSCAN_SKIP_PORTS=443,8444,2222 ENABLE_BANONCE=0 | head -1)
if [[ -f "$f" ]]; then
    check "без ban-once: исключение в обоих правилах бана (ps4, ps6)" 2 \
          "$(grep -E 'meter (ps4|ps6) ' "$f" | grep -cF "ct state new $SKIP ")"
    rm -f "$f"
else
    checkf "DRY_RUN без ban-once не дал файла"
fi
out=$(gen 'PORTSCAN_SKIP_PORTS=443;rm -rf /')
check "мусор в PORTSCAN_SKIP_PORTS — отказ до генерации" "нет файла 1" \
      "$(printf '%s\n' "$out" | head -1) $(printf '%s\n' "$out" | grep -c 'ждал порты через запятую')"
check "ручка сохраняется в protect.conf (save_conf)" 1 "$(grep -c ' PORTSCAN_SKIP_PORTS ' "$PROTECT")"

# ─── 9. /24-метры syn4net_22 и obs4net из шаблона ───────────────────────────
# Флот ставил их скриптом subnet-meter-rollout (vpn) после каждого ре-рана protect, и
# до этой правки их не было (29.09.2026). Имена метров прежние: по ним сверяют
# fleet-consistency, node-facts и na-perekatka-verify (vpn), а subnet-meter-rollout
# находит правило и не ставит второе. Генерация — та же gen из раздела 7.
echo "== 9. SSH_NET_RATE и OBS_NET_PORTS: /24-метры в шаблоне =="
line() { grep -n -e "$1" "$2" | head -1 | cut -d: -f1; }
f=$(gen SSH_NET_RATE=20 SSH_NET_BURST=40 OBS_NET_PORTS=443,8444 TCP_PORTS=443,8444 | head -1)
if [[ ! -f "$f" ]]; then
    checkf "DRY_RUN с /24-метрами не дал файла: $(gen SSH_NET_RATE=20 OBS_NET_PORTS=443 | tail -2)"
else
    check "syn4net_22: /24, 20 в минуту, burst 40, drop" 1 \
          "$(grep -cF 'tcp dport { 22 } ct state new meter syn4net_22 size 65535 { ip saddr and 255.255.255.0 limit rate over 20/minute burst 40 packets } drop' "$f")"
    s=$(line 'meter syn4net_22 ' "$f"); h=$(line 'meter ssh4 ' "$f")
    check "syn4net_22 стоит перед пер-IP ssh4" 1 "$(( ${s:-0} > 0 && ${s:-0} < ${h:-0} ))"
    check "obs4net: клиентские порты, 300 в минуту, burst 600, лог [na subnet-client]" 1 \
          "$(grep -cF 'tcp dport { 443, 8444 } ct state new meter obs4net size 65535 { ip saddr and 255.255.255.0 limit rate over 300/minute burst 600 packets } limit rate 5/second log prefix "[na subnet-client] " level info' "$f")"
    o=$(line 'meter obs4net ' "$f"); c=$(line '# сервисные TCP-порты' "$f"); k=$(line 'meter cc4_' "$f")
    check "obs4net под комментарием сервисных портов и до первого cc4_ (якоря subnet-meter-rollout)" 1 \
          "$(( ${c:-0} > 0 && ${c:-0} < ${o:-0} && ${o:-0} < ${k:-0} ))"
    check "у obs4net нет вердикта — только лог" 0 "$(grep 'meter obs4net ' "$f" | grep -cE ' (drop|accept)$')"
    rm -f "$f"
fi
f=$(gen | head -1)
if [[ -f "$f" ]]; then
    check "без ручек — как в апстриме: ни syn4net_22, ни obs4net" "0 0" \
          "$(grep -c 'syn4net_22' "$f") $(grep -c 'obs4net' "$f")"
    rm -f "$f"
else
    checkf "DRY_RUN без ручек не дал файла"
fi
out=$(env PATH="$A/bin:$PATH" REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=1 FW_MODE=strict ENABLE_CROWDSEC=0 \
      OBS_NET_PORTS=443,8444 TCP_PORTS=443,2087 "$WBASH" "$A/scripts/protect.sh" 2>&1) || true
check "порт наблюдения вне TCP_PORTS — предупреждение с номером" 1 \
      "$(printf '%s\n' "$out" | grep -c 'OBS_NET_PORTS: порта 8444 нет в TCP_PORTS')"
rm -f "$(printf '%s\n' "$out" | sed -n 's/.*Посмотреть: cat //p' | tail -1)"
out=$(gen 'OBS_NET_PORTS=443;rm -rf /')
check "мусор в OBS_NET_PORTS — отказ до генерации" "нет файла 1" \
      "$(printf '%s\n' "$out" | head -1) $(printf '%s\n' "$out" | grep -c 'OBS_NET_PORTS:')"
out=$(gen SSH_NET_RATE=abc)
check "SSH_NET_RATE не число — отказ" "нет файла 1" \
      "$(printf '%s\n' "$out" | head -1) $(printf '%s\n' "$out" | grep -c "SSH_NET_RATE='abc'")"
out=$(gen SSH_NET_RATE=20 SSH_NET_BURST=0)
check "включённый метр с burst 0 — отказ" "нет файла 1" \
      "$(printf '%s\n' "$out" | head -1) $(printf '%s\n' "$out" | grep -c 'SSH_NET_BURST=0 при SSH_NET_RATE=20')"
out=$(gen OBS_NET_PORTS=443 OBS_NET_RATE=0)
check "наблюдение с порогом 0 — отказ" "нет файла 1" \
      "$(printf '%s\n' "$out" | head -1) $(printf '%s\n' "$out" | grep -c 'OBS_NET_RATE=0 ')"
check "пять ручек сохраняются в protect.conf (save_conf)" 1 \
      "$(grep -c ' SSH_NET_RATE SSH_NET_BURST OBS_NET_PORTS OBS_NET_RATE OBS_NET_BURST ' "$PROTECT")"
check "пустой OBS_NET_PORTS из ENV переживает чтение conf (NA_CONF_EMPTY_OK)" 1 \
      "$(grep -cE '^NA_CONF_EMPTY_OK=".* OBS_NET_PORTS( |")' "$REPO_ROOT/scripts/lib/common.sh")"
# Полный apply с ручками, затем ре-ран без ENV: метры берутся из protect.conf. Раздел
# последний — дальше этот conf никому не мешает.
set +e
PATH="$A/bin:$PATH" SSH_NET_RATE=20 SSH_NET_BURST=40 OBS_NET_PORTS=443 TCP_PORTS=443 ENABLE_CROWDSEC=0 \
    NA_FWA_LOCK="$A/state/fleet-fw-apply.lock" REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
    "$WBASH" "$A/scripts/protect.sh" >"$A/apply9.log" 2>&1
rc=$?
set -e
check "apply с /24-метрами отработал (exit 0)" 0 "$rc"
check "protect.conf: SSH_NET_RATE и OBS_NET_PORTS записаны" 2 \
      "$(grep -cE '^: "\$\{(SSH_NET_RATE:=20|OBS_NET_PORTS=443)\}"$' "$A/conf/protect.conf")"
f=$(gen | head -1)
if [[ -f "$f" ]]; then
    check "ре-ран без ENV: оба метра на месте (из protect.conf)" "1 1" \
          "$(grep -c 'meter syn4net_22 ' "$f") $(grep -c 'meter obs4net ' "$f")"
    rm -f "$f"
else
    checkf "ре-ран без ENV не дал файла"
fi
f=$(gen OBS_NET_PORTS= | head -1)
if [[ -f "$f" ]]; then
    check "пустой OBS_NET_PORTS в ENV снимает наблюдение поверх conf" "1 0" \
          "$(grep -c 'meter syn4net_22 ' "$f") $(grep -c 'meter obs4net ' "$f")"
    rm -f "$f"
else
    checkf "ре-ран с пустым OBS_NET_PORTS не дал файла"
fi

echo
echo "итого: ok=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]]
