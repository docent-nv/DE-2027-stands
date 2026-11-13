#!/bin/bash
# =====================================================================================
#  ДЭ-2027 (КИМ 09.02.06-1-2027): развёртывание стендов на Proxmox VE / Альт Виртуализация
#  Обёртка над PVE-ASDaC-BASH: скачивает закреплённую версию скрипта и конфигурацию
#  из репозитория, проверяет образы ВМ и запускает развёртывание.
#
#  Запуск на узле PVE (Shell, под root):
#    (r=docent-nv/DE-2027-stands b=main; curl -sfOL "https://raw.githubusercontent.com/$r/$b/deploy.sh" && bash deploy.sh; rm -f deploy.sh)
#
#  Дополнительные аргументы передаются в PVE-ASDaC-BASH.sh, например «тихая» установка
#  10 стендов варианта 1:   bash deploy.sh -var 1 -n 1-10 -si
#
#  Переменные окружения (необязательно):
#    DE27_REPO    репозиторий GitHub        (по умолчанию docent-nv/DE-2027-stands)
#    DE27_BRANCH  ветка                     (по умолчанию main)
#    DE27_IMG     каталог с образами        (по умолчанию /root/de27/images)
#    DE27_LOCAL=1 взять файлы из каталога рядом с deploy.sh, а не скачивать
# =====================================================================================

set -u
REPO=${DE27_REPO:-docent-nv/DE-2027-stands}
BRANCH=${DE27_BRANCH:-main}
IMG_DIR=${DE27_IMG:-/root/de27/images}
WORK=/root/de27/run
RAW="https://raw.githubusercontent.com/$REPO/$BRANCH"

c_ok=$'\e[1;32m'; c_err=$'\e[1;31m'; c_warn=$'\e[1;33m'; c_info=$'\e[1;36m'; c_0=$'\e[m'
ok()   { echo "${c_ok}[OK]${c_0} $*"; }
warn() { echo "${c_warn}[!]${c_0} $*"; }
err()  { echo "${c_err}[ОШИБКА]${c_0} $*" >&2; }
info() { echo "${c_info}[i]${c_0} $*"; }

[[ $EUID -eq 0 ]] || { err "запустите от имени root (Shell узла Proxmox)"; exit 1; }
command -v pvesh >/dev/null && command -v qm >/dev/null || { err "это не узел Proxmox VE / Альт Виртуализации (нет pvesh/qm)"; exit 1; }

SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$WORK/configs" "$IMG_DIR"
cd "$WORK" || exit 1

# ---------- 1. Получение скрипта и конфигурации ----------
if [[ ${DE27_LOCAL:-0} == 1 && -f "$SRC_DIR/PVE-ASDaC-BASH.sh" ]]; then
    cp -f "$SRC_DIR/PVE-ASDaC-BASH.sh" "$WORK/" && cp -f "$SRC_DIR/configs/de27.conf" "$WORK/configs/"
    ok "Файлы взяты из локального каталога $SRC_DIR"
else
    info "Скачивание из $RAW"
    for f in PVE-ASDaC-BASH.sh configs/de27.conf; do
        curl -sfL --retry 3 -o "$WORK/$f" "$RAW/$f" || { err "не удалось скачать $RAW/$f (проверьте Интернет, DNS и что репозиторий публичный)"; exit 1; }
    done
    ok "Скрипт и конфигурация скачаны в $WORK"
fi
chmod +x "$WORK/PVE-ASDaC-BASH.sh"

# Если образы лежат не в /root/de27/images — подменяем путь в копии конфигурации
[[ "$IMG_DIR" != /root/de27/images ]] && sed -i "s#/root/de27/images#${IMG_DIR%/}#g" "$WORK/configs/de27.conf"

# ---------- 2. Проверка образов ----------
declare -A NEED=(
    [Alt-SRV_11.1.qcow2]='Альт Сервер 11.1 (ISP, HQ-SRV, BR-SRV)'
    [Alt-WS_11.2.qcow2]='Альт Рабочая станция 11.2 (HQ-CLI)'
    [EcoRouterOS.qcow2]='EcoRouterOS Pesto (HQ-RTR, BR-RTR)'
    [NGFW.qcow2]='Ideco NGFW v23 (BR-FW)'
    [Additional.iso]='Additional.iso (только вариант 2 — задания 2 и 3)'
)
echo; info "Проверка образов в $IMG_DIR"
missing=0
for f in Alt-SRV_11.1.qcow2 Alt-WS_11.2.qcow2 EcoRouterOS.qcow2 NGFW.qcow2 Additional.iso; do
    p="$IMG_DIR/$f"
    if [[ ! -r "$p" ]]; then
        warn "нет файла ${c_warn}$f${c_0} — ${NEED[$f]}"; ((missing++)); continue
    fi
    size=$(du -h --apparent-size "$p" | cut -f1)
    if [[ $f == *.qcow2 ]]; then
        # формат и размер берём с верхнего уровня JSON: в новых версиях qemu-img (Proxmox 8.2+ / 9)
        # первым идёт блок "children" с "format": "file" — это слой файла, а не формат образа
        read -r fmt vsz < <(qemu-img info --output=json "$p" 2>/dev/null \
            | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j.get("format","?"), j.get("virtual-size",0))' 2>/dev/null)
        vsz=${vsz:-0}
        [[ $fmt == qcow2 ]] || { err "$f: формат «${fmt:-не определён}», ожидается qcow2"; ((missing++)); continue; }
        ok "$f  (${size} на диске, виртуальный размер $((vsz/1024/1024/1024)) ГБ)"
    else
        ok "$f  ($size)"
    fi
done
if [[ -f "$IMG_DIR/images.sha256" ]]; then
    info "Сверка контрольных сумм по $IMG_DIR/images.sha256"
    (cd "$IMG_DIR" && sha256sum -c --quiet images.sha256) && ok "контрольные суммы совпадают" || warn "есть несовпадения контрольных сумм — образ мог скопироваться с ошибкой"
fi
if (( missing )); then
    echo
    warn "Не хватает файлов: $missing. Варианту 1 нужны образы Альт + EcoRouter + Ideco;"
    warn "варианту 2 (задания 2 и 3) — ещё и Additional.iso."
    read -r -p "Продолжить всё равно? [y/N]: " a </dev/tty; [[ $a =~ ^[yYдД]$ ]] || exit 1
fi

# ---------- 3. Ресурсы узла ----------
mem_gb=$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo)
info "ОЗУ узла: ${mem_gb} ГБ. Один стенд требует ≈ 23 ГБ (без учёта KSM)."

# ---------- 4. Запуск PVE-ASDaC-BASH ----------
echo; info "Запуск: ./PVE-ASDaC-BASH.sh -c configs/de27.conf -z $*"
echo
exec ./PVE-ASDaC-BASH.sh -c configs/de27.conf -z "$@"
