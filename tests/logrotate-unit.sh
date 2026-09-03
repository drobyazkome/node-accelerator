#!/usr/bin/env bash
#
# logrotate-unit.sh — ИСПОЛНЯЕТ секцию «ротация логов ноды» из optimize.sh в песочнице
# против стабов logrotate/systemctl. Секция — top-level код, целиком optimize в CI не
# гоняется, поэтому оба бага раскатки v4.0 жили именно здесь (issues #24, #25).
#
# Что стережём:
#   1. ре-ран на настроенной ноде НЕ падает (backup_file без 2-го аргумента, #24);
#   2. конфликт с чужой стансой решает вердикт САМОГО logrotate, а не сравнение строк:
#      конфликтная маска отдаётся чужой стансе, наша станса переписывается (#25);
#   3. глоб-маски попадают в стансу КАК ЗАДАНЫ — не раскрытыми шеллом в явные пути по
#      живым файлам (иначе лог нового vhost'а никогда не начал бы ротироваться);
#   4. чужой дубликат вне наших масок не зацикливает и нашу стансу не трогает;
#   5. полная уступка всех масок = стансы нет и есть внятное инфо-сообщение.
#
# Не требует root/сети/systemd. Запуск: bash tests/logrotate-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
LRD="$T/etc/logrotate.d"
REC="$T/rec"
export LRD REC
mkdir -p "$T/bin" "$LRD" "$T/systemd" "$T/backup" "$REC" \
         "$T/var/log/nginx" "$T/var/log/remnanode"

# Секции нужен bash ≥ 4.4 (пустые массивы под set -u) — на нодах и CI он есть всегда,
# а вот системный bash macOS древний: берём первый, который умеет.
pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4 для исполнения секции"; exit 1; }

# живые файлы под масками — ловушка для глоб-раскрытия шеллом (свойство 3)
touch "$T/var/log/nginx/access.log" "$T/var/log/nginx/error.log" "$T/var/log/remnanode/node.log"
: > "$REC/foreign-claims.txt"
: > "$REC/foreign-dup.txt"

# ── Достаём секцию 8b из optimize.sh (top-level код между маркерами разделов) ───
awk '/^# ─── 8b\./{f=1} /^# ─── 9\./{f=0} f' "$REPO_ROOT/scripts/optimize.sh" > "$T/section.raw"
[ -s "$T/section.raw" ] || { echo "[x] не смог извлечь секцию 8b из optimize.sh"; exit 1; }
# системные пути → в песочницу (sed НЕ рескантит подстановку, самоссылка $LRD безопасна)
sed -e "s#/etc/logrotate\.d#$LRD#g" \
    -e "s#/etc/logrotate\.conf#$T/etc/logrotate.conf#g" \
    -e "s#/etc/systemd/system/#$T/systemd/#g" \
    "$T/section.raw" > "$T/section.sh"

cat > "$T/wrap.sh" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
BACKUP="$T/backup"
STATE_DIR="$T/state"
. "$T/section.sh"
WRAP
STATE="$T/state"

# ── Стабы ───────────────────────────────────────────────────────────────────────
cat > "$T/bin/systemctl" <<'ST'
#!/bin/sh
exit 0
ST
# Эмуляция «logrotate -d <conf>»: дедуп по РАСКРЫТЫМ файлам, как у настоящего.
#   foreign-claims.txt — пути, которые уже держат чужие стансы: дубликат, если путь
#                        всё ещё покрыт маской нашей стансы (1-я строка na-node-logs);
#   foreign-dup.txt    — дубликат между двумя ЧУЖИМИ стансами (репортится всегда).
cat > "$T/bin/logrotate" <<'LR'
#!/bin/bash
set -f
printf '%s\n' "$*" >> "$REC/logrotate.argv"
rc=0
if [ -f "$LRD/na-node-logs" ] && [ -s "$REC/foreign-claims.txt" ]; then
    masks="$(head -1 "$LRD/na-node-logs" | sed 's/ *{.*$//')"
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        for m in $masks; do
            # shellcheck disable=SC2053  # маска без кавычек — намеренный glob-матч
            if [[ "$p" == $m ]]; then
                echo "error: foreign:1 duplicate log entry for $p" >&2
                echo "error: found error in file foreign, skipping" >&2
                rc=1
                break
            fi
        done
    done < "$REC/foreign-claims.txt"
fi
if [ -s "$REC/foreign-dup.txt" ]; then
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        echo "error: other:1 duplicate log entry for $p" >&2
        rc=1
    done < "$REC/foreign-dup.txt"
fi
exit "$rc"
LR
chmod +x "$T/bin/systemctl" "$T/bin/logrotate"
export PATH="$T/bin:$PATH"

MASKS="$T/var/log/nginx/*.log $T/var/log/remnanode/*.log"
STANZA="$LRD/na-node-logs"

fail=0
expect()     { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✔ $d"; else echo "  ✘ $d"; fail=1; fi; }
expect_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✘ $d"; fail=1; else echo "  ✔ $d"; fi; }

run_section() {
    : > "$REC/logrotate.argv"
    NA_LOG_PATHS="$MASKS" "$WBASH" "$T/wrap.sh" > "$T/out.log" 2>&1
}

# ── Кейс 1: первый прогон, конфликтов нет ───────────────────────────────────────
echo "== первый прогон (чисто) =="
expect "секция отработала (rc=0)" run_section
expect "станса создана" test -f "$STANZA"
expect "глоб nginx в стансе КАК ЗАДАН (не раскрыт по живым файлам)" grep -qF "$T/var/log/nginx/*.log" "$STANZA"
expect "глоб remnanode в стансе" grep -qF "$T/var/log/remnanode/*.log" "$STANZA"
expect_not "явных раскрытых путей в стансе нет" grep -qF "access.log" "$STANZA"
expect "сервис-юнит записан" test -f "$T/systemd/na-logrotate.service"
expect "таймер-юнит записан" test -f "$T/systemd/na-logrotate.timer"

# ── Кейс 2: ре-ран на настроенной ноде (issue #24) ──────────────────────────────
echo "== ре-ран (станса уже существует — #24) =="
expect "ре-ран НЕ упал" run_section
expect "станса на месте после ре-рана" test -f "$STANZA"
expect "бэкап прежней стансы сделан" test -f "$T/backup/na-node-logs"

# ── Кейс 3: чужая станса держит наш путь (issue #25) ────────────────────────────
echo "== конфликт с чужой стансой (#25) =="
rm -f "$STANZA"
# текстуально НЕ совпадает с нашей маской — строковый греп такое не ловил
printf '%s\n' "$T/var/log/nginx/*" '{ daily }' > "$LRD/nginx-legacy"
printf '%s\n' "$T/var/log/nginx/access.log" > "$REC/foreign-claims.txt"
expect "секция отработала (rc=0)" run_section
expect "станса создана (не снесена целиком)" test -f "$STANZA"
expect_not "конфликтная маска nginx ОТДАНА чужой стансе" grep -qF "$T/var/log/nginx" "$STANZA"
expect "неконфликтная маска remnanode осталась" grep -qF "$T/var/log/remnanode/*.log" "$STANZA"
expect "warn про уступку маски напечатан" grep -q "отдана чужой стансе" "$T/out.log"
expect "после переписывания стансы вердикт перепроверен" test "$(wc -l < "$REC/logrotate.argv")" -ge 2
# issue #40: владелец найден, у него нет maxsize — об этом сказано САМИМ модулем, а не «проверь сам»
expect "владелец уступленной маски назван (nginx-legacy)" grep -q "nginx-legacy" "$T/out.log"
expect "у владельца daily БЕЗ maxsize — warn об этом" grep -q "daily БЕЗ maxsize/size" "$T/out.log"
expect "состояние уступки записано (logrotate.ceded)" test -s "$STATE/logrotate.ceded"
expect "в ceded: маска → владелец → none" grep -qE "^$T/var/log/nginx/\*\.log	$LRD/nginx-legacy	none$" "$STATE/logrotate.ceded"
expect "в owned: оставшаяся маска remnanode" grep -qF "$T/var/log/remnanode/*.log" "$STATE/logrotate.owned"
expect_not "в owned НЕТ уступленной маски nginx" grep -qF "$T/var/log/nginx" "$STATE/logrotate.owned"

# ── Кейс 3b: у чужой стансы maxsize ЕСТЬ — уступка без тревоги о капе ───────────
echo "== чужая станса с maxsize (кап есть) =="
rm -f "$STANZA"
printf '%s\n' "$T/var/log/nginx/*" '{' '    weekly' '    maxsize 500M' '}' > "$LRD/nginx-legacy"
expect "секция отработала (rc=0)" run_section
expect "уступка есть, кап найден — info, не warn" grep -q "кап на размер работает" "$T/out.log"
expect_not "warn «БЕЗ maxsize» НЕ напечатан" grep -q "БЕЗ maxsize/size" "$T/out.log"
expect "в ceded: capped" grep -qE "	capped$" "$STATE/logrotate.ceded"

# ── Кейс 4: чужой дубликат вне наших масок ──────────────────────────────────────
echo "== чужой дубликат (не наши маски) =="
rm -f "$STANZA" "$LRD/nginx-legacy"
: > "$REC/foreign-claims.txt"
printf '%s\n' "/var/log/other/app.log" > "$REC/foreign-dup.txt"
expect "секция отработала (rc=0)" run_section
expect "наши маски не тронуты" grep -qF "$T/var/log/nginx/*.log" "$STANZA"
expect "warn про чужой конфликт напечатан" grep -q "вне наших масок" "$T/out.log"
expect "цикл не зациклился (ровно один вызов -d)" test "$(wc -l < "$REC/logrotate.argv")" -eq 1
expect_not "уступок нет — logrotate.ceded снят" test -e "$STATE/logrotate.ceded"
expect "owned содержит обе маски" test "$(grep -c . "$STATE/logrotate.owned")" -eq 2

# ── Кейс 5: все маски уже у чужих станс ─────────────────────────────────────────
echo "== полная уступка всех масок =="
rm -f "$STANZA"
: > "$REC/foreign-dup.txt"
printf '%s\n' "$T/var/log/nginx/access.log" "$T/var/log/remnanode/node.log" > "$REC/foreign-claims.txt"
printf '%s\n' "$T/var/log/nginx/*" '{ daily }' > "$LRD/nginx-legacy"
printf '%s\n' "$T/var/log/remnanode/*.log" '{ weekly }' > "$LRD/vpn-node-logs"
expect "секция отработала (rc=0)" run_section
expect "станса не создана (все пути чужие)" test ! -f "$STANZA"
expect "полная уступка — это WARN, а не info (#40)" grep -q "\[!\].*свою НЕ создаю" "$T/out.log"
expect "ceded перечисляет обе маски" test "$(grep -c . "$STATE/logrotate.ceded")" -eq 2
expect "второй владелец (vpn-node-logs, weekly без maxsize) назван" grep -q "vpn-node-logs: там weekly БЕЗ maxsize" "$T/out.log"
expect_not "owned снят (нашей стансы нет)" test -e "$STATE/logrotate.owned"

# ── Кейс 6: ENABLE_LOGROTATE=0 — состояние прошлых прогонов не должно врать ────
echo "== ENABLE_LOGROTATE=0 снимает состояние =="
: > "$REC/logrotate.argv"
ENABLE_LOGROTATE=0 NA_LOG_PATHS="$MASKS" "$WBASH" "$T/wrap.sh" > "$T/out.log" 2>&1 || true
expect_not "ceded снят при ENABLE_LOGROTATE=0" test -e "$STATE/logrotate.ceded"

if [ "$fail" -ne 0 ]; then echo "LOGROTATE-UNIT: FAIL"; exit 1; fi
echo "LOGROTATE-UNIT: OK (ре-ран жив, конфликты решает вердикт logrotate, глобы не раскрываются, чужие дубликаты не наши, уступка видна: владелец/кап/состояние)"
