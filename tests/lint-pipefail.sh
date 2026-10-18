#!/usr/bin/env bash
#
# lint-pipefail.sh — запрещает `cmd | grep -q` в скриптах, живущих под `set -o pipefail`.
#
# grep -q выходит на ПЕРВОМ совпадении и закрывает пайп. Если команда слева пишет ещё —
# она ловит SIGPIPE, пайплайн под pipefail отдаёт 141, и условие становится ложным ровно
# тогда, когда совпадение ЕСТЬ. Так в v4.1.2 через раз пропадал сенсор лога анти-скана
# (справка journalctl 5 КБ уходит двумя записями), никогда не срабатывало предупреждение
# «сокеты на cubic» (ss -tin — мегабайты) и не виден был дубликат в `logrotate -d`.
#
# Разрешено: источник — одиночный `printf '%s[\n]' "$var"` (одна маленькая запись, писать
# после выхода grep нечего) и строки с пометкой `# pipefail-ok` (осознанное исключение).
# Правильные замены: вывод в переменную + `[[ $v == *pat* ]]` / `grep -q … <<<"$v"`,
# `grep -c` (дочитывает вход), `awk '…{f=1} END{exit !f}'`.
#
# Второе правило (v4.2-rw4) — ранний выход читателя под `set -e` + pipefail: `| head`,
# `| grep -m`, `| awk '…exit…'` (кроме exit в END). Там 141 не путает условие, а
# обрывает скрипт. Так protect.sh падал на узлах с двумя маршрутами по умолчанию:
# `ip route show default | awk '…{print; exit}'`, ip пишет маршруты разными write
# (timeweb, 18.10.2026: 26 и 12 из 2000 прогонов). Код без -e (diagnose, na-report) и
# heredoc-хелперы со своим `set` без -e/pipefail правило не трогает: регион хелпера —
# от строки `<<ТЕГ` (тег — заглавными) до `ТЕГ`, его режим — по `set` внутри. Мимо
# правила: `|| true` в той же строке и пометка `# pipefail-ok`. Замены: awk с флагом
# (`!f {…; f = 1}`), `awk 'NR==1'` вместо `head -1`.
#
# Не требует root/сети. Запуск: bash tests/lint-pipefail.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bad=0
for f in install.sh scripts/*.sh scripts/lib/*.sh; do
    # common.sh своего set не имеет, но исполняется внутри скриптов с pipefail
    if [[ "$f" != scripts/lib/common.sh ]] && ! grep -qE '^set -[a-z]*o pipefail' "$f"; then
        continue
    fi
    while IFS= read -r hit; do
        line="${hit#*:}"   # grep -n по одному файлу: «N:строка»
        code="${line%%#*}"   # хвостовой комментарий не в счёт
        [[ "$line" == *'# pipefail-ok'* ]] && continue
        [[ "$code" =~ \|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q ]] || continue
        if [[ "$code" =~ printf\ \'%s(\\n)?\'\ \"\$[A-Za-z_][A-Za-z_0-9]*\"[[:space:]]*\|[[:space:]]*grep ]]; then
            continue
        fi
        echo "  [x] $f:${hit%%:*}: $(sed -E 's/^[[:space:]]+//' <<<"$line")"
        bad=$((bad+1))
    done < <(grep -nE '\|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q' "$f" || true)
done

# «N:строка» для строк под set -e + pipefail с ранним выходом читателя конвейера
early_exit_hits() {
    LC_ALL=C awk -v F="$1" '
    function strict(s) { return s ~ /^set -[a-z]*e[a-z]*o pipefail/ }
    BEGIN { q = "[\047\"]?"; start = "(^|[^<])<<-?[ \t]*" q "[A-Z_][A-Z_0-9]*" q "([ \t;)|&>]|$)" }
    FNR == NR {                      # проход 1: регионы heredoc и их режим
        if (!inh) {
            if (match($0, start)) {
                t = substr($0, RSTART, RLENGTH); sub(/^[^<]*<<-?[ \t]*/, "", t)
                gsub(/[^A-Z_0-9]/, "", t); inh = 1; tag = t; hs = FNR; hm = 0
            } else if (strict($0)) top = 1
        } else if ($0 ~ ("^[ \t]*" tag "$")) {
            for (k = hs + 1; k < FNR; k++) reg[k] = hm
            inh = 0
        } else if (strict($0)) hm = 1
        next
    }
    {                                # проход 2: правила
        if (F == "scripts/lib/common.sh") top = 1   # исполняется внутри protect/install
        if (!((FNR in reg) ? reg[FNR] : top)) next
        if ($0 ~ /^[ \t]*#/ || $0 ~ /# pipefail-ok/) next
        code = $0; sub(/[ \t]#.*$/, "", code)
        if (code ~ /\|\|[ \t]*(true|:)([ \t;)]|$)/) next
        hit = 0
        if (code ~ /\|[ \t]*head([ \t]|$)/) hit = 1
        else if (code ~ /\|[ \t]*grep[ \t]+(-[A-Za-z]+[ \t]+)*-[A-Za-z]*m/) hit = 1
        else if (match(code, /\|[ \t]*awk[^|]*[{; \t]exit([^A-Za-z_0-9]|$)/)) {
            seg = substr(code, RSTART, RLENGTH)
            if (seg !~ /END[ \t]*\{[^}]*exit/) hit = 1
        }
        if (hit) print FNR ":" $0
    }' "$1" "$1"
}

bad2=0
for f in install.sh scripts/*.sh scripts/lib/*.sh; do
    while IFS= read -r hit; do
        echo "  [x] $f:${hit%%:*}: $(sed -E 's/^[[:space:]]+//' <<<"${hit#*:}")"
        bad2=$((bad2+1))
    done < <(early_exit_hits "$f")
done

if [[ "$bad" -gt 0 || "$bad2" -gt 0 ]]; then
    [[ "$bad" -gt 0 ]] && echo "LINT-PIPEFAIL: FAIL — $bad пайп(ов) в grep -q под pipefail (SIGPIPE → ложное «нет»)"
    [[ "$bad2" -gt 0 ]] && echo "LINT-PIPEFAIL: FAIL — $bad2 ранних выходов (head / grep -m / awk exit) под set -e + pipefail (SIGPIPE → 141, обрыв скрипта)"
    exit 1
fi
echo "LINT-PIPEFAIL: OK (под pipefail нет пайпов в grep -q; под set -e + pipefail — ранних выходов читателя)"
