#!/usr/bin/env bash
#
# psi-unit.sh — ИСПОЛНЯЕТ секцию «PSI (psi=1 в cmdline)» из optimize.sh и парный блок
# отката из rollback.sh в песочнице против стаба update-grub и фейкового
# /etc/default/grub. Секции — top-level код, целиком optimize в CI не гоняется.
#
# Что стережём (issue #37):
#   1. ENABLE_PSI=0 (дефолт) не трогает /etc/default/grub ВООБЩЕ — в т.ч. не снимает
#      psi=1, дописанный оператором;
#   2. ENABLE_PSI=1 дописывает psi=1 ВНУТРЬ кавычек GRUB_CMDLINE_LINUX_DEFAULT и зовёт
#      update-grub; ре-ран не дублирует параметр;
#   3. маркер optimize.installed получает psi=1 ТОЛЬКО когда параметр дописали мы —
#      чужой psi=1 не присваиваем, и rollback его не снимет;
#   4. ядро без CONFIG_PSI и нестандартная строка GRUB — молча пропускаем/предупреждаем,
#      прогон не падает (секция не должна ронять optimize посреди мутаций);
#   5. rollback снимает psi=1 только при psi=1 в маркере и оставляет строку опрятной.
#
# Не требует root/сети/systemd. Запуск: bash tests/psi-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
GRUB="$T/etc/default/grub"
REC="$T/rec"
export REC
mkdir -p "$T/bin" "$T/etc/default" "$T/boot" "$T/state" "$T/backup" "$REC"

pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4"; exit 1; }

fail=0
expect()     { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✔ $d"; else echo "  ✘ $d"; fail=1; fi; }
expect_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✘ $d"; fail=1; else echo "  ✔ $d"; fi; }

# ── Стабы ───────────────────────────────────────────────────────────────────────
cat > "$T/bin/update-grub" <<'UG'
#!/bin/sh
echo "update-grub" >> "$REC/update-grub.calls"
exit 0
UG
chmod +x "$T/bin/update-grub"

# Секция написана под GNU sed (`sed -i` без суффикса). На BSD sed (macOS) у -i суффикс
# обязателен — заворачиваем, иначе тест «падал бы» на платформе, а не на коде.
REAL_SED="$(command -v sed)"
if "$REAL_SED" --version 2>/dev/null | grep -q GNU; then
    printf '#!/bin/sh\nexec %s "$@"\n' "$REAL_SED" > "$T/bin/sed"
else
    cat > "$T/bin/sed" <<SEDW
#!/usr/bin/env bash
args=()
for a in "\$@"; do
    if [ "\$a" = "-i" ]; then args+=( -i '' ); else args+=( "\$a" ); fi
done
exec "$REAL_SED" "\${args[@]}"
SEDW
fi
chmod +x "$T/bin/sed"
export PATH="$T/bin:$PATH"

# ── Достаём секцию 2b из optimize.sh и блок отката из rollback.sh ───────────────
sandbox() {   # системные пути → в песочницу
    "$REAL_SED" -e "s#/etc/default/grub#$GRUB#g" \
                -e "s#/boot/config-#$T/boot/config-#g" \
                -e "s#/proc/pressure/cpu#$T/proc/pressure/cpu#g"
}
awk '/^# ─── 2b\./{f=1} /^# ─── 3\./{f=0} f' "$REPO_ROOT/scripts/optimize.sh" | sandbox > "$T/section.sh"
[ -s "$T/section.sh" ] || { echo "[x] не смог извлечь секцию 2b из optimize.sh"; exit 1; }

awk '/^    # psi=1 в GRUB_CMDLINE_LINUX_DEFAULT/{f=1} f{print} f && /^    fi$/{exit}' \
    "$REPO_ROOT/scripts/rollback.sh" | sandbox > "$T/rollback-psi.sh"
[ -s "$T/rollback-psi.sh" ] || { echo "[x] не смог извлечь psi-блок из rollback.sh"; exit 1; }

cat > "$T/wrap-optimize.sh" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
STATE_DIR="$T/state"
BACKUP="$T/backup"
REBOOT_NEEDED=0
REBOOT_WHY=""
. "$T/section.sh"
{ echo "PSI_MARK=\$PSI_MARK"; echo "REBOOT_NEEDED=\$REBOOT_NEEDED"; echo "REBOOT_WHY=\$REBOOT_WHY"; } > "$T/vars"
WRAP

cat > "$T/wrap-rollback.sh" <<WRAP
#!/usr/bin/env bash
set -uo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
STATE_DIR="$T/state"
. "$T/rollback-psi.sh"
WRAP

# ── Хелперы кейсов ──────────────────────────────────────────────────────────────
set_grub()   { printf '%s\n' 'GRUB_TIMEOUT=5' "GRUB_CMDLINE_LINUX_DEFAULT=\"$1\"" 'GRUB_CMDLINE_LINUX=""' > "$GRUB"; }
kernel_cfg() { printf '%s\n' "$@" > "$T/boot/config-$(uname -r)"; }
cmdline()    { grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB"; }
marker()     { printf '%s\n' "installed_at=now" "nic=ens18" "psi=$1" > "$T/state/optimize.installed"; }
reset_case() { : > "$REC/update-grub.calls"; rm -f "$T/state/optimize.installed" "$T/vars" "$T/backup"/*; }
run_opt()    { rc=0; "$WBASH" "$T/wrap-optimize.sh" > "$T/out" 2>&1 || rc=$?; return 0; }
run_rb()     { rc=0; "$WBASH" "$T/wrap-rollback.sh" > "$T/out" 2>&1 || rc=$?; return 0; }
var()        { grep "^$1=" "$T/vars" | cut -d= -f2-; }
ug_calls()   { local n; n="$(wc -l < "$REC/update-grub.calls" 2>/dev/null || echo 0)"; echo "${n// /}"; }

kernel_cfg 'CONFIG_PSI=y' 'CONFIG_PSI_DEFAULT_DISABLED=y'

# ── Кейс 1: дефолт (ENABLE_PSI=0) ничего не трогает ─────────────────────────────
echo "== ENABLE_PSI=0 (дефолт) =="
reset_case; set_grub "quiet"
run_opt
expect "секция отработала (rc=0)" test "$rc" -eq 0
expect "grub не тронут" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"'
expect "update-grub не звался" test "$(ug_calls)" -eq 0
expect "маркер psi=0" test "$(var PSI_MARK)" = "0"

echo "== ENABLE_PSI=0 при уже стоящем psi=1 оператора =="
reset_case; set_grub "quiet psi=1"
run_opt
expect "чужой psi=1 НЕ снят" grep -q 'psi=1' "$GRUB"
expect "маркер psi=0 (не наш параметр)" test "$(var PSI_MARK)" = "0"

# ── Кейс 2: ENABLE_PSI=1 дописывает ─────────────────────────────────────────────
echo "== ENABLE_PSI=1 =="
reset_case; set_grub "quiet"
ENABLE_PSI=1 run_opt
expect "секция отработала (rc=0)" test "$rc" -eq 0
expect "psi=1 дописан ВНУТРЬ кавычек" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet psi=1"'
expect "update-grub позван" test "$(ug_calls)" -eq 1
expect "маркер psi=1 (наш параметр)" test "$(var PSI_MARK)" = "1"
expect "затребован reboot" test "$(var REBOOT_NEEDED)" = "1"
expect "причина ребута названа" grep -q 'psi=1' <<<"$(var REBOOT_WHY)"
expect "бэкап grub сделан" test -f "$T/backup/grub"
expect "остальные строки grub целы" grep -qx 'GRUB_TIMEOUT=5' "$GRUB"

echo "== ре-ран с ENABLE_PSI=1 (идемпотентность) =="
: > "$REC/update-grub.calls"
marker 1                       # маркер, каким его написал бы optimize на прошлом прогоне
ENABLE_PSI=1 run_opt
expect "psi=1 ровно один" test "$(grep -c 'psi=1' "$GRUB")" -eq 1
expect "строка не дублирует параметр" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet psi=1"'
expect "update-grub повторно не звался" test "$(ug_calls)" -eq 0
expect "маркер psi=1 перенесён с прошлого прогона" test "$(var PSI_MARK)" = "1"

echo "== psi=1 от оператора + ENABLE_PSI=1, маркера нет =="
reset_case; set_grub "quiet psi=1"
ENABLE_PSI=1 run_opt
expect "маркер psi=0 — параметр не присваиваем" test "$(var PSI_MARK)" = "0"
expect "grub не переписан" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet psi=1"'

echo "== пустое значение GRUB_CMDLINE_LINUX_DEFAULT =="
reset_case; set_grub ""
ENABLE_PSI=1 run_opt
expect "без ведущего пробела" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="psi=1"'

# ── Кейс 3: ядро без CONFIG_PSI ─────────────────────────────────────────────────
echo "== ядро без CONFIG_PSI =="
reset_case; set_grub "quiet"; kernel_cfg 'CONFIG_PSI is not set'
ENABLE_PSI=1 run_opt
expect "секция отработала (rc=0)" test "$rc" -eq 0
expect "grub не тронут" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"'
expect "сказано про CONFIG_PSI" grep -q 'CONFIG_PSI' "$T/out"
kernel_cfg 'CONFIG_PSI=y' 'CONFIG_PSI_DEFAULT_DISABLED=y'

# ── Кейс 4: нестандартная строка и отсутствие grub ──────────────────────────────
echo "== нестандартный GRUB_CMDLINE_LINUX_DEFAULT =="
reset_case
printf '%s\n' "GRUB_CMDLINE_LINUX_DEFAULT='quiet'" > "$GRUB"
ENABLE_PSI=1 run_opt
expect "секция отработала (rc=0)" test "$rc" -eq 0
expect "файл не тронут" test "$(cmdline)" = "GRUB_CMDLINE_LINUX_DEFAULT='quiet'"
expect "предупреждение напечатано" grep -q 'вручную' "$T/out"
expect "маркер psi=0" test "$(var PSI_MARK)" = "0"

echo "== /etc/default/grub нет (контейнер/не-GRUB) =="
reset_case; rm -f "$GRUB"
ENABLE_PSI=1 run_opt
expect "секция отработала (rc=0)" test "$rc" -eq 0
expect "файл не создан на пустом месте" test ! -f "$GRUB"
expect "инфо про отсутствие grub" grep -q 'GRUB' "$T/out"

# ── Кейс 5: откат ───────────────────────────────────────────────────────────────
echo "== rollback: psi=1 в маркере → снимаем =="
reset_case; set_grub "quiet psi=1"; marker 1
run_rb
expect "блок отработал (rc=0)" test "$rc" -eq 0
expect "psi=1 убран, строка опрятна" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"'
expect "update-grub позван" test "$(ug_calls)" -eq 1

echo "== rollback: psi в середине значения =="
reset_case; set_grub "quiet psi=1 splash"; marker 1
run_rb
expect "двойных пробелов не осталось" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"'

echo "== rollback: единственный параметр =="
reset_case; set_grub "psi=1"; marker 1
run_rb
expect "значение пустое, кавычки на месте" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT=""'

echo "== rollback: psi=0 в маркере → чужой параметр не трогаем =="
reset_case; set_grub "quiet psi=1"; marker 0
run_rb
expect "psi=1 на месте" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet psi=1"'
expect "update-grub не звался" test "$(ug_calls)" -eq 0

echo "== rollback: маркера нет вовсе =="
reset_case; set_grub "quiet psi=1"
run_rb
expect "psi=1 на месте" test "$(cmdline)" = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet psi=1"'
expect "update-grub не звался" test "$(ug_calls)" -eq 0

# ── Регрессия: на v4.0.1 ручки не было вовсе ───────────────────────────────────
echo "== код v4.0.1 (регрессия; пропускается без тега v4.0.1) =="
if git -C "$REPO_ROOT" show v4.0.1:scripts/optimize.sh > "$T/old-optimize.sh" 2>/dev/null; then
    expect_not "в v4.0.1 секции PSI нет" grep -q '^# ─── 2b\.' "$T/old-optimize.sh"
    expect_not "в v4.0.1 ручки ENABLE_PSI нет" grep -q 'ENABLE_PSI' "$T/old-optimize.sh"
    git -C "$REPO_ROOT" show v4.0.1:scripts/rollback.sh > "$T/old-rollback.sh" 2>/dev/null || true
    expect_not "в v4.0.1 откат psi=1 не делался" grep -q 'psi=1' "$T/old-rollback.sh"
else
    echo "  • ветка main недоступна — сравнение с v4.0.1 пропущено"
fi

if [ "$fail" -ne 0 ]; then echo "PSI-UNIT: FAIL"; exit 1; fi
echo "PSI-UNIT: OK (ENABLE_PSI=0 не трогает grub, =1 дописывает идемпотентно, маркер только для своего psi=1, откат снимает только свой)"
