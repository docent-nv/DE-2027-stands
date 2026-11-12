#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Предварительная автоматическая проверка ЗАДАНИЯ 1 ДЭ-2027 (КИМ 09.02.06-1-2027), варианты 1–4.

Запуск на узле Proxmox VE под root:
    python3 check_z1.py -n 1-10                 # стенды 1..10, вариант определяется автоматически
    python3 check_z1.py -n 3 --variant 2 -v     # стенд 3, принудительно вариант 2, подробный вывод

Как собираются данные:
  * ВМ на Альт (ISP, HQ-SRV, BR-SRV, HQ-CLI) — через гостевой агент QEMU (qm guest exec);
  * EcoRouter (HQ-RTR, BR-RTR) — через последовательную консоль ВМ (serial0), вход под net_admin;
  * BR-FW (Ideco) — косвенно: соседство OSPF на BR-RTR и связность с BR-SRV;
  * теги VLAN — из конфигурации ВМ в Proxmox.

Результат — ПРЕДВАРИТЕЛЬНАЯ оценка по критериям КИМ (Задание 1). Итоговые баллы выставляет эксперт:
всё, что скрипт не смог проверить, помечается «ПРОВЕРИТЬ ВРУЧНУЮ».
"""
import argparse, base64, csv, datetime, ipaddress, json, os, re, socket, subprocess, sys, time

# ----------------------------------------------------------------------------------------------
# Параметры задания
# ----------------------------------------------------------------------------------------------
VARIANTS = {
    1: dict(srv=111, cli=211, mgmt=811, hq='172.16.10.0/28', br='172.16.20.0/28', uid=2011, port=2011),
    2: dict(srv=112, cli=212, mgmt=812, hq='172.16.30.0/28', br='172.16.40.0/28', uid=2012, port=2012),
    3: dict(srv=113, cli=213, mgmt=813, hq='172.16.50.0/28', br='172.16.60.0/28', uid=2013, port=2013),
    4: dict(srv=114, cli=214, mgmt=814, hq='172.16.70.0/28', br='172.16.80.0/28', uid=2014, port=2014),
}
DOMAIN = 'au-team.irpo'
PASSWORD = 'P@ssw0rd'
BANNER = 'Authorized access only'
TUN_NET = ipaddress.ip_network('10.10.10.0/24')
INET_IP = '77.88.8.8'
FQDN = {'HQ-RTR': 'hq-rtr', 'BR-RTR': 'br-rtr', 'BR-FW': 'br-fw', 'HQ-SRV': 'hq-srv', 'HQ-CLI': 'hq-cli', 'BR-SRV': 'br-srv'}

# Критерии КИМ, задание 1: (код, название, максимальный балл)
CRITERIA = [
    ('K1', 'Подинтерфейсы на HQ-RTR (VLAN)', 2),
    ('K2', 'Маршрутизация и NAT на ISP', 1),
    ('K3', 'Туннель между офисами HQ и BR', 2),
    ('K4', 'Динамическая маршрутизация (OSPF)', 3),
    ('K5', 'NAT в офисах, выход в Интернет', 2),
    ('K6', 'DHCP на HQ-RTR', 2),
    ('K7', 'DNS: зоны, записи, пересылка', 3),
    ('K8', 'Разделение на подсети', 1),
    ('K9', 'IP-адреса, имена и время', 2),
    ('K10', 'Локальные учётные записи', 2),
    ('K11', 'Удалённый доступ SSH', 3),
    ('K12', 'Часовой пояс', 1),
    ('K13', 'Отчёт (ГОСТ Р 7.0.97-2016)', 1),
]

C = dict(ok='\033[1;32m', bad='\033[1;31m', warn='\033[1;33m', info='\033[1;36m', dim='\033[2m', b='\033[1m', x='\033[0m')
if not sys.stdout.isatty():
    C = {k: '' for k in C}

ARGS = None


def log(msg):
    if ARGS and ARGS.verbose:
        print(f"{C['dim']}  · {msg}{C['x']}")


# ----------------------------------------------------------------------------------------------
# Proxmox
# ----------------------------------------------------------------------------------------------
def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'timeout'


def pool_vms(pool):
    rc, out, _ = run(['pvesh', 'get', f'/pools/{pool}', '--output-format', 'json'])
    if rc != 0:
        return None
    data = json.loads(out)
    members = data.get('members', data if isinstance(data, list) else [])
    vms = {}
    for m in members:
        if m.get('type') in ('qemu', None) and 'vmid' in m:
            vms[m.get('name')] = dict(vmid=m['vmid'], node=m.get('node'), status=m.get('status'))
    return vms


def vm_config(vmid):
    rc, out, _ = run(['qm', 'config', str(vmid)])
    cfg = {}
    for line in out.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            cfg[k.strip()] = v.strip()
    return cfg


def guest_exec(vmid, script, timeout=60):
    """Выполняет bash-скрипт в ВМ через гостевой агент. Возвращает stdout или None."""
    b64 = base64.b64encode(script.encode()).decode()
    cmd = ['qm', 'guest', 'exec', str(vmid), '--timeout', str(timeout), '--', '/bin/bash', '-c',
           f'echo {b64} | base64 -d | /bin/bash']
    rc, out, err = run(cmd, timeout=timeout + 15)
    if rc != 0:
        log(f'guest exec {vmid}: rc={rc} {err.strip()[:200]}')
        return None
    try:
        j = json.loads(out)
    except ValueError:
        return None
    return j.get('out-data', '') + ('' if j.get('exited', 1) else '')


def agent_ok(vmid):
    rc, _, _ = run(['qm', 'agent', str(vmid), 'ping'], timeout=15)
    return rc == 0


def sections(text):
    """Разбор вывода вида '### ключ' → {ключ: текст}."""
    res, key = {}, None
    for line in (text or '').splitlines():
        if line.startswith('### '):
            key = line[4:].strip()
            res[key] = []
        elif key is not None:
            res[key].append(line)
    return {k: '\n'.join(v).strip() for k, v in res.items()}


# ----------------------------------------------------------------------------------------------
# Последовательная консоль EcoRouter
# ----------------------------------------------------------------------------------------------
class SerialConsole:
    def __init__(self, vmid, transcript=None):
        self.path = os.path.join(ARGS.serial_dir, f'{vmid}.serial0')
        self.sock = None
        self.buf = ''
        self.transcript = transcript

    def open(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(1.0)
        self.sock.connect(self.path)

    def send(self, s):
        self.sock.sendall(s.encode())

    def read_until(self, patterns, timeout=10.0):
        """Читает, пока не встретится один из regex-шаблонов. Отвечает на постраничный вывод."""
        end = time.time() + timeout
        start_len = len(self.buf)
        while time.time() < end:
            try:
                data = self.sock.recv(65536)
                if data:
                    chunk = data.decode('utf-8', 'replace')
                    self.buf += chunk
                    if self.transcript:
                        self.transcript.write(chunk)
            except socket.timeout:
                pass
            tail = self.buf[start_len:]
            if re.search(r'--\s*[Mm]ore\s*--', tail[-200:]):
                self.send(' ')
                self.buf = self.buf[:start_len] + re.sub(r'--\s*[Mm]ore\s*--', '', tail)
                continue
            for i, p in enumerate(patterns):
                if re.search(p, tail[-400:]):
                    return i, tail
        return -1, self.buf[start_len:]

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


PROMPT = r'(?m)^[\w.\-]+(\([\w\-./]+\))?[>#]\s*$'


def eco_collect(vmid, name):
    """Логинится на EcoRouter через serial0 и снимает конфигурацию. Возвращает dict или None."""
    tr = None
    if ARGS.save_console:
        os.makedirs(ARGS.out, exist_ok=True)
        tr = open(os.path.join(ARGS.out, f'console_{name}_{vmid}.log'), 'w', encoding='utf-8')
    con = SerialConsole(vmid, tr)
    result = dict(login=None, running='', ospf='', route='')
    try:
        con.open()
    except Exception as e:
        log(f'{name}: нет доступа к serial0 ({e})')
        return None
    try:
        con.send('\r')
        idx, _ = con.read_until([r'[Ll]ogin:\s*$', PROMPT, r'[Pp]assword:\s*$'], 8)
        if idx == -1:
            con.send('\r')
            idx, _ = con.read_until([r'[Ll]ogin:\s*$', PROMPT, r'[Pp]assword:\s*$'], 8)
        if idx == 1:          # уже залогинен (сессия осталась открытой)
            result['login'] = 'session'
            con.send('end\r')
            con.read_until([PROMPT], 5)
        elif idx in (0, 2):
            for user, pwd in [('net_admin', PASSWORD)] + ([tuple(ARGS.eco_fallback.split(':', 1))] if ARGS.eco_fallback else []):
                if idx == 2:
                    con.send('\r')
                    con.read_until([r'[Ll]ogin:\s*$'], 5)
                con.send(user + '\r')
                con.read_until([r'[Pp]assword:\s*$'], 6)
                con.send(pwd + '\r')
                idx, _ = con.read_until([PROMPT, r'[Ll]ogin:\s*$', r'[Ii]ncorrect|[Ff]ail'], 10)
                if idx == 0:
                    result['login'] = user
                    break
                idx = 0
            if not result['login']:
                return dict(login=False)
        else:
            log(f'{name}: консоль не отвечает приглашением')
            return None

        def cmd(c, t=15):
            con.send(c + '\r')
            _, out = con.read_until([PROMPT], t)
            lines = out.splitlines()
            return '\n'.join(l for l in lines[1:] if not re.match(PROMPT, l))

        cmd('enable', 5)
        cmd('terminal length 0', 5)
        result['running'] = cmd('show running-config', 25)
        result['ospf'] = cmd('show ip ospf neighbor', 10)
        result['route'] = cmd('show ip route', 10)
        result['ifbrief'] = cmd('show ip interface brief', 10)
        if result['login'] != 'session':
            con.send('exit\r')
            con.read_until([r'[Ll]ogin:\s*$'], 3)
    finally:
        con.close()
        if tr:
            tr.close()
    return result


def parse_eco(running):
    """Разбор running-config EcoRouter в структуру."""
    cfg = dict(hostname=None, domain=None, users={}, ifaces={}, ports={}, routes=[], ospf=None,
               nat_pools={}, nat_rules=[], dhcp=None, ip_pools={}, tz=None)
    cur_kind, cur, sub = None, None, None
    for raw in running.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith('!'):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            cur_kind, cur, sub = None, None, None
            m = re.match(r'hostname\s+(\S+)', s)
            if m: cfg['hostname'] = m.group(1); continue
            m = re.match(r'ip domain-name\s+(\S+)', s)
            if m: cfg['domain'] = m.group(1); continue
            m = re.match(r'username\s+(\S+)', s)
            if m: cur_kind, cur = 'user', m.group(1); cfg['users'][cur] = {'role': None}; continue
            m = re.match(r'interface\s+(\S+)', s)
            if m: cur_kind, cur = 'if', m.group(1); cfg['ifaces'][cur] = {'ip': [], 'nat': None, 'tunnel': None, 'ospf_md5': False, 'ospf_auth': False, 'dhcp': False}; continue
            m = re.match(r'port\s+(\S+)', s)
            if m: cur_kind, cur = 'port', m.group(1); cfg['ports'][cur] = {}; continue
            m = re.match(r'ip route\s+(\S+)(?:\s+(\S+))?\s+(\S+)', s)
            if m: cfg['routes'].append(s); continue
            m = re.match(r'router ospf(\s+\d+)?$', s)
            if m: cur_kind = 'ospf'; cfg['ospf'] = {'passive_default': False, 'no_passive': [], 'passive': [], 'networks': [], 'rid': None}; continue
            m = re.match(r'ip nat pool\s+(\S+)\s+(\S+)', s)
            if m: cfg['nat_pools'][m.group(1)] = m.group(2); continue
            if s.startswith('ip nat source'):
                cfg['nat_rules'].append(s); continue
            m = re.match(r'ip pool\s+(\S+)\s+(\S+)', s)
            if m: cfg['ip_pools'][m.group(1)] = m.group(2); continue
            m = re.match(r'dhcp-server\s+(\d+)', s)
            if m: cur_kind = 'dhcp'; cfg['dhcp'] = cfg['dhcp'] or {'pools': {}}; continue
            m = re.match(r'ntp timezone\s+(\S+)', s)
            if m: cfg['tz'] = m.group(1).lower(); continue
            continue
        # вложенные строки
        if cur_kind == 'user':
            m = re.match(r'role\s+(\S+)', s)
            if m: cfg['users'][cur]['role'] = m.group(1)
        elif cur_kind == 'if':
            d = cfg['ifaces'][cur]
            m = re.match(r'ip address\s+(\S+)(?:\s+(\S+))?', s)
            if m:
                a = m.group(1) if '/' in m.group(1) else f'{m.group(1)}/{m.group(2)}'
                try:
                    d['ip'].append(ipaddress.ip_interface(a))
                except ValueError:
                    pass
            m = re.match(r'ip nat\s+(inside|outside)', s)
            if m: d['nat'] = m.group(1)
            m = re.match(r'ip tunnel\s+(\S+)\s+(\S+)\s+mode\s+(\S+)', s)
            if m: d['tunnel'] = (m.group(1), m.group(2), m.group(3).lower())
            if re.match(r'ip ospf authentication message-digest', s): d['ospf_auth'] = True
            if re.match(r'ip ospf message-digest-key\s+\d+\s+md5\s+\S+', s): d['ospf_md5'] = True
            if re.match(r'dhcp-server\s+\d+', s): d['dhcp'] = True
            if s == 'no ip ospf passive': d['ospf_active'] = True   # FRR 8+: пассивность задаётся на интерфейсе
        elif cur_kind == 'port':
            m = re.match(r'service-instance\s+(\S+)', s)
            if m: sub = m.group(1); cfg['ports'][cur][sub] = {'encap': None, 'iface': None}; continue
            if sub:
                m = re.match(r'encapsulation\s+(.+)', s)
                if m: cfg['ports'][cur][sub]['encap'] = m.group(1)
                m = re.match(r'connect ip interface\s+(\S+)', s)
                if m: cfg['ports'][cur][sub]['iface'] = m.group(1)
        elif cur_kind == 'ospf':
            o = cfg['ospf']
            if s == 'passive-interface default': o['passive_default'] = True
            m = re.match(r'no passive-interface\s+(\S+)', s)
            if m: o['no_passive'].append(m.group(1))
            m = re.match(r'passive-interface\s+(\S+)$', s)
            if m and m.group(1) != 'default': o['passive'].append(m.group(1))
            m = re.match(r'network\s+(\S+)(?:\s+(\S+))?\s+area\s+(\S+)', s)
            if m:
                n = m.group(1) if '/' in m.group(1) else f'{m.group(1)}/{m.group(2)}'
                try: o['networks'].append(ipaddress.ip_network(n, strict=False))
                except ValueError: pass
            m = re.match(r'(?:ospf\s+)?router-id\s+(\S+)', s)
            if m: o['rid'] = m.group(1)
        elif cur_kind == 'dhcp':
            m = re.match(r'pool\s+(\S+)', s)
            if m: sub = m.group(1); cfg['dhcp']['pools'][sub] = {}; continue
            if sub:
                m = re.match(r'(mask|gateway|dns|domain-name)\s+(\S+)', s)
                if m: cfg['dhcp']['pools'][sub][m.group(1)] = m.group(2)
    if cfg['ospf']:
        for nm, d in cfg['ifaces'].items():
            if d.get('ospf_active') and nm not in cfg['ospf']['no_passive']:
                cfg['ospf']['no_passive'].append(nm)
    return cfg


# ----------------------------------------------------------------------------------------------
# Сбор данных с ВМ на Альт
# ----------------------------------------------------------------------------------------------
BASE = r'''
echo "### hostname"; hostname
echo "### tz"; timedatectl show -p Timezone --value 2>/dev/null || readlink -f /etc/localtime
echo "### addr"; ip -4 -o addr show scope global
echo "### route"; ip -4 route show default
echo "### resolv"; cat /etc/resolv.conf 2>/dev/null
'''
ISP_EXTRA = r'''
echo "### fwd"; sysctl -n net.ipv4.ip_forward
echo "### nat"; { iptables -t nat -S 2>/dev/null; nft list ruleset 2>/dev/null; } | grep -i masquerade
echo "### inet"; ping -c2 -W2 77.88.8.8 >/dev/null 2>&1 && echo ok || echo fail
'''
def user_script(user):
    """Учётная запись: passwd, sudo без пароля, проверка пароля P@ssw0rd по хешу (crypt или libcrypt)."""
    return rf'''
echo "### passwd"; getent passwd {user}
echo "### sudo"; su -s /bin/bash {user} -c 'sudo -n true' >/dev/null 2>&1 && echo ok || echo fail
echo "### pwcheck"
h=$( (cat /etc/tcb/{user}/shadow 2>/dev/null; getent shadow {user} 2>/dev/null) | head -1 | cut -d: -f2)
if [ -n "$h" ] && command -v python3 >/dev/null; then
  H="$h" python3 -W ignore - <<'PY' 2>/dev/null || echo unknown
import os, ctypes, ctypes.util
h = os.environ["H"]
try:
    import crypt; r = crypt.crypt("{PASSWORD}", h)
except Exception:
    lib = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
    lib.crypt.restype = ctypes.c_char_p
    r = (lib.crypt(b"{PASSWORD}", h.encode()) or b"").decode()
print("ok" if r == h else "bad")
PY
else echo unknown; fi
'''


SRV_EXTRA = user_script('sshuser') + r'''
echo "### sshd"; sshd -T 2>/dev/null | grep -iE '^(port|allowusers|maxauthtries|banner) '
echo "### banner"; f=$(sshd -T 2>/dev/null | awk '/^banner /{print $2}'); [ -n "$f" ] && [ "$f" != none ] && cat "$f" 2>/dev/null
'''
# Маршрутизаторы на Альт (развёртывание «вариант 2»): Linux + FRR
ALT_RTR_EXTRA = r'''
echo "### links"; ip -d -o link show
echo "### fwd"; sysctl -n net.ipv4.ip_forward
echo "### nat"; { iptables -t nat -S 2>/dev/null; nft list ruleset 2>/dev/null; } | grep -iE 'masquerade|snat'
echo "### frr"; vtysh -c 'show running-config' 2>/dev/null
echo "### ospfnb"; vtysh -c 'show ip ospf neighbor' 2>/dev/null
echo "### dhcpd"; cat /etc/dhcp/dhcpd.conf 2>/dev/null; cat /etc/dnsmasq.conf /etc/dnsmasq.d/*.conf 2>/dev/null | grep -v '^#'
''' + user_script('net_admin')
DNS_EXTRA = r'''
echo "### bind"; for s in bind named; do st=$(systemctl is-active $s 2>/dev/null); [ "$st" = active ] && break; done; echo "${st:-unknown}"
q(){ if command -v dig >/dev/null; then dig +short +time=2 +tries=1 @127.0.0.1 "$@"; else host -W 2 -t "$2" "$1" 127.0.0.1 2>/dev/null | awk '/has address|domain name pointer/{print $NF}'; fi; }
for n in hq-rtr br-rtr br-fw hq-srv hq-cli br-srv docker web; do echo "### A $n"; q $n.au-team.irpo A; done
echo "### FWD"; q ya.ru A | head -3
'''


def ptr_script(ips):
    s = 'q(){ if command -v dig >/dev/null; then dig +short +time=2 +tries=1 @127.0.0.1 -x "$1"; else host -W 2 "$1" 127.0.0.1 2>/dev/null | awk \'/pointer/{print $NF}\'; fi; }\n'
    for ip in ips:
        s += f'echo "### PTR {ip}"; q {ip}\n'
    return s


def conn_script(targets, port=None, ssh_host=None):
    s = ''
    for t in targets:
        s += f'echo "### ping {t}"; ping -c2 -W2 {t} >/dev/null 2>&1 && echo ok || echo fail\n'
    s += 'echo "### web"; curl -s -o /dev/null -m 8 -w "%{http_code}" http://ya.ru 2>/dev/null; echo\n'
    s += 'echo "### resolve"; getent hosts ya.ru | head -1\n'
    if port and ssh_host:
        s += (f'echo "### sshbanner"; timeout 12 ssh -o BatchMode=yes -o StrictHostKeyChecking=no '
              f'-o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -p {port} sshuser@{ssh_host} true 2>&1 | head -5\n')
    return s


def ips_of(sec):
    """[(iface, ip_interface, dynamic)] из вывода ip -4 -o addr."""
    res = []
    for line in (sec or '').splitlines():
        m = re.match(r'\d+:\s+(\S+)\s+inet\s+(\S+)', line)
        if m:
            try:
                res.append((m.group(1), ipaddress.ip_interface(m.group(2)), 'dynamic' in line))
            except ValueError:
                pass
    return res


def alt_router_cfg(d):
    """Маршрутизатор на Альт (Linux + FRR) → та же структура, что parse_eco()."""
    cfg = parse_eco(d.get('frr', ''))          # router ospf, interface … ip ospf … из FRR
    cfg['linux'] = True
    fq = d.get('hostname', '')
    cfg['hostname'], _, cfg['domain'] = fq.partition('.')
    cfg['domain'] = cfg['domain'] or None
    cfg['tz'] = d.get('tz', '')
    ifs = cfg['ifaces']
    for name, ip, _dyn in ips_of(d.get('addr')):
        name = name.split('@')[0]
        ifs.setdefault(name, {'ip': [], 'nat': None, 'tunnel': None, 'ospf_md5': False, 'ospf_auth': False, 'dhcp': False})
        if ip not in ifs[name]['ip']:
            ifs[name]['ip'].append(ip)
    cfg['ports'] = {'linux': {}}
    for line in (d.get('links') or '').splitlines():
        m = re.match(r'\d+:\s+([^:@\s]+)', line)
        if not m:
            continue
        nm = m.group(1)
        v = re.search(r'\bvlan protocol 802\.1Q id (\d+)', line)
        if v:
            cfg['ports']['linux'][nm] = {'encap': f'dot1q {v.group(1)}', 'iface': nm}
        g = re.search(r'\bgre remote (\S+) local (\S+)', line)
        if g and nm in ifs:
            ifs[nm]['tunnel'] = (g.group(2), g.group(1), 'gre')
    for rule in (d.get('nat') or '').splitlines():
        m = re.search(r'-o\s+(\S+)', rule) or re.search(r'oifname\s+"?([\w.\-]+)', rule)
        if m and m.group(1) in ifs:
            ifs[m.group(1)]['nat'] = 'outside'
            cfg['nat_rules'].append(rule)
    dh = d.get('dhcpd') or ''
    for i, m in enumerate(re.finditer(r'range\s+([\d.]+)\s+([\d.]+)|dhcp-range=(?:[\w:]+,)?([\d.]+),([\d.]+)', dh)):
        a, b = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        cfg['ip_pools'][f'pool{i + 1}'] = f'{a}-{b}'
    ok_sudo = d.get('sudo') == 'ok'
    if d.get('passwd'):
        cfg['users']['net_admin'] = {'role': 'admin' if ok_sudo else None}
    return cfg


# ----------------------------------------------------------------------------------------------
# Проверка одного стенда
# ----------------------------------------------------------------------------------------------
class Result:
    def __init__(self):
        self.items = {c[0]: dict(level=None, notes=[], manual=False) for c in CRITERIA}

    def note(self, k, ok, text):
        self.items[k]['notes'].append((ok, text))

    def set(self, k, level, manual=False):
        self.items[k]['level'] = level
        self.items[k]['manual'] = manual


def private(ip):
    return ip.ip.is_private


def check_stand(n, forced_variant):
    vms = None
    for tpl in ([ARGS.pool] if ARGS.pool else ['DE27_Z1_stand_{}', 'DE27_Z1alt_stand_{}']):
        pool = tpl.format(n)
        vms = pool_vms(pool)
        if vms:
            break
    R = Result()
    info = dict(stand=n, pool=pool, variant=None)
    if not vms:
        print(f"{C['bad']}Стенд {n}: пул {pool} не найден{C['x']}")
        return None, info
    need = ['ISP', 'HQ-RTR', 'BR-RTR', 'BR-FW', 'HQ-SRV', 'HQ-CLI', 'BR-SRV']
    miss = [x for x in need if x not in vms]
    if miss:
        print(f"{C['warn']}Стенд {n}: в пуле нет ВМ {', '.join(miss)}{C['x']}")

    # --- вариант
    def tag_of(name):
        if name not in vms: return None
        cfg = vm_config(vms[name]['vmid'])
        for k, v in cfg.items():
            if re.match(r'net\d+$', k):
                m = re.search(r'tag=(\d+)', v)
                return int(m.group(1)) if m else 0
        return None
    tag_srv, tag_cli = tag_of('HQ-SRV'), tag_of('HQ-CLI')
    var = forced_variant
    if not var:
        for k, vv in VARIANTS.items():
            if tag_srv == vv['srv'] or tag_cli == vv['cli']:
                var = k
    info['variant'] = var
    if not var:
        print(f"{C['warn']}Стенд {n}: вариант не определён по тегам VLAN (HQ-SRV={tag_srv}, HQ-CLI={tag_cli}). "
              f"Укажите --variant.{C['x']}")
        return None, info
    V = VARIANTS[var]

    # --- сбор: Альт
    data = {}
    for name, extra in [('ISP', ISP_EXTRA), ('HQ-SRV', SRV_EXTRA + DNS_EXTRA), ('BR-SRV', SRV_EXTRA), ('HQ-CLI', '')]:
        if name not in vms: continue
        vmid = vms[name]['vmid']
        if vms[name].get('status') != 'running' or not agent_ok(vmid):
            data[name] = None
            log(f'{name} ({vmid}): ВМ выключена или нет гостевого агента')
            continue
        data[name] = sections(guest_exec(vmid, BASE + extra))
        data[name]['_ips'] = ips_of(data[name].get('addr'))
        log(f'{name}: собрано {len(data[name])} разделов')
    # --- сбор: маршрутизаторы (EcoRouter — консоль serial0; Альт — гостевой агент)
    eco = {}
    for name in ('HQ-RTR', 'BR-RTR'):
        if name not in vms or vms[name].get('status') != 'running':
            eco[name] = None
            continue
        vmid = vms[name]['vmid']
        if agent_ok(vmid):
            d = sections(guest_exec(vmid, BASE + ALT_RTR_EXTRA))
            if d:
                eco[name] = dict(login='net_admin' if d.get('passwd') and d.get('pwcheck') != 'bad' else False,
                                 running=d.get('frr', ''), ospf=d.get('ospfnb', ''), cfg=alt_router_cfg(d), alt=d)
                log(f'{name}: маршрутизатор на Альт, данные получены через гостевой агент')
                continue
        raw = eco_collect(vmid, name)
        eco[name] = raw
        if raw and raw.get('running'):
            raw['cfg'] = parse_eco(raw['running'])
    # BR-FW на Альт (развёртывание «вариант 2») — имя, адреса, часовой пояс
    if 'BR-FW' in vms and vms['BR-FW'].get('status') == 'running' and agent_ok(vms['BR-FW']['vmid']):
        data['BR-FW'] = sections(guest_exec(vms['BR-FW']['vmid'], BASE))
        data['BR-FW']['_ips'] = ips_of(data['BR-FW'].get('addr'))

    def ipv4(name, net_filter=None):
        d = data.get(name)
        if not d: return []
        return [x for x in d['_ips'] if not net_filter or x[1].ip in net_filter]

    hq_srv_ip = (ipv4('HQ-SRV') or [(None, None, None)])[0][1]
    br_srv_ip = (ipv4('BR-SRV') or [(None, None, None)])[0][1]
    hq_cli_ip = (ipv4('HQ-CLI') or [(None, None, None)])[0][1]

    # --- связность (вторая фаза: адреса уже известны)
    conn = {}
    if data.get('HQ-SRV') and br_srv_ip:
        conn['HQ-SRV'] = sections(guest_exec(vms['HQ-SRV']['vmid'], conn_script([str(br_srv_ip.ip), INET_IP], V['port'], str(br_srv_ip.ip))))
    if data.get('BR-SRV') and hq_srv_ip:
        tg = [str(hq_srv_ip.ip), INET_IP] + ([str(hq_cli_ip.ip)] if hq_cli_ip else [])
        conn['BR-SRV'] = sections(guest_exec(vms['BR-SRV']['vmid'], conn_script(tg, V['port'], str(hq_srv_ip.ip))))
    if data.get('HQ-CLI') and br_srv_ip:
        conn['HQ-CLI'] = sections(guest_exec(vms['HQ-CLI']['vmid'], conn_script([str(br_srv_ip.ip), INET_IP])))
    if data.get('HQ-SRV') and hq_srv_ip and br_srv_ip:
        data['HQ-SRV'].update(sections(guest_exec(vms['HQ-SRV']['vmid'], ptr_script([str(hq_srv_ip.ip), str(br_srv_ip.ip)]))))

    def ping(frm, to):
        c = conn.get(frm) or {}
        return c.get(f'ping {to}') == 'ok'

    hq = eco.get('HQ-RTR') or {}
    br = eco.get('BR-RTR') or {}
    hqc, brc = hq.get('cfg'), br.get('cfg')
    for name, e in (('HQ-RTR', hq), ('BR-RTR', br)):
        if e == {} or e is None:
            R.note('K9', None, f'{name}: конфигурация не прочитана (нет доступа к консоли serial0)')
        elif e.get('login') is False:
            R.note('K10', False, f'{name}: вход под net_admin / P@ssw0rd не удался')

    # ===================== K1: подинтерфейсы HQ-RTR =====================
    ok_tags = (tag_srv == V['srv']) + (tag_cli == V['cli'])
    R.note('K1', tag_srv == V['srv'], f'Proxmox: тег VLAN HQ-SRV = {tag_srv} (нужно {V["srv"]})')
    R.note('K1', tag_cli == V['cli'], f'Proxmox: тег VLAN HQ-CLI = {tag_cli} (нужно {V["cli"]})')
    if hqc:
        encs = {}
        for port, sis in hqc['ports'].items():
            for si, d in sis.items():
                m = re.search(r'dot1q\s+(\d+)', d.get('encap') or '')
                if m and d.get('iface'):
                    encs[int(m.group(1))] = d['iface']
        got = [v for v in (V['srv'], V['cli'], V['mgmt']) if v in encs and hqc['ifaces'].get(encs[v], {}).get('ip')]
        for v in (V['srv'], V['cli'], V['mgmt']):
            R.note('K1', v in encs, f'HQ-RTR: VLAN {v} → интерфейс {encs.get(v, "нет")}')
        lvl = 2 if len(got) == 3 and ok_tags == 2 else (1 if got else 0)
        R.set('K1', lvl)
    else:
        gw_ok = data.get('HQ-SRV') and (data['HQ-SRV'].get('route') or '')
        R.set('K1', 1 if ok_tags == 2 else 0, manual=True)
        R.note('K1', None, 'VLAN 8xx (управление) проверить вручную: конфигурация HQ-RTR не прочитана')

    # ===================== K2: ISP =====================
    isp = data.get('ISP')
    if isp:
        ips = [x[1] for x in isp['_ips']]
        in_hq = any(ip in ipaddress.ip_network(V['hq']) for ip in ips)
        in_br = any(ip in ipaddress.ip_network(V['br']) for ip in ips)
        fwd = isp.get('fwd') == '1'
        nat = bool(isp.get('nat'))
        R.note('K2', in_hq, f'ISP: адрес в сети {V["hq"]} (к HQ-RTR)')
        R.note('K2', in_br, f'ISP: адрес в сети {V["br"]} (к BR-RTR)')
        R.note('K2', fwd, f'ISP: net.ipv4.ip_forward = {isp.get("fwd")}')
        R.note('K2', nat, 'ISP: правило MASQUERADE')
        R.note('K2', isp.get('inet') == 'ok', 'ISP: доступ в Интернет')
        offices = sum([ping('HQ-SRV', INET_IP) or ping('HQ-CLI', INET_IP), ping('BR-SRV', INET_IP)])
        R.set('K2', 2 if (in_hq and in_br and fwd and nat and offices == 2) else (1 if (fwd and nat and offices >= 1) else 0))
    else:
        R.set('K2', None, manual=True); R.note('K2', None, 'ISP: нет гостевого агента — проверить вручную')

    # ===================== K3: туннель =====================
    def tun(cfg):
        if not cfg: return None
        for nm, d in cfg['ifaces'].items():
            if d.get('tunnel'):
                return nm, d
        return None
    th, tb = tun(hqc), tun(brc)
    for who, t in (('HQ-RTR', th), ('BR-RTR', tb)):
        if t:
            nm, d = t
            ip_ok = any(i.ip in TUN_NET and i.network.prefixlen >= 30 for i in d['ip'])
            R.note('K3', d['tunnel'][2] == 'gre' and ip_ok, f'{who}: {nm} {", ".join(map(str, d["ip"]))} mode {d["tunnel"][2]} ({d["tunnel"][0]} → {d["tunnel"][1]})')
        elif (eco.get(who) or {}).get('cfg'):
            R.note('K3', False, f'{who}: туннельный интерфейс не найден')
    cross = ping('HQ-SRV', str(br_srv_ip.ip)) if br_srv_ip else False
    if hqc and brc:
        both = bool(th and tb and th[1]['tunnel'][2] == 'gre' and tb[1]['tunnel'][2] == 'gre')
        mirror = both and th[1]['tunnel'][0] == tb[1]['tunnel'][1] and th[1]['tunnel'][1] == tb[1]['tunnel'][0]
        masks = both and all(any(i.ip in TUN_NET and i.network.prefixlen >= 30 for i in t[1]['ip']) for t in (th, tb))
        R.set('K3', 2 if (mirror and masks and cross) else (1 if (th or tb) else 0))
    else:
        R.set('K3', 1 if cross else 0, manual=True)
        R.note('K3', cross, 'Связность HQ-SRV → BR-SRV (косвенный признак работы туннеля)')

    # ===================== K4: OSPF =====================
    if hqc and brc:
        o_ok, part = True, False
        for who, cfg, t in (('HQ-RTR', hqc, th), ('BR-RTR', brc, tb)):
            o = cfg.get('ospf')
            if not o:
                R.note('K4', False, f'{who}: router ospf не настроен'); o_ok = False; continue
            part = True
            tname = t[0] if t else 'tunnel.0'
            R.note('K4', o['passive_default'], f'{who}: passive-interface default')
            R.note('K4', tname in o['no_passive'], f'{who}: no passive-interface {tname}')
            md5 = bool(t and t[1]['ospf_md5'] and t[1]['ospf_auth'])
            R.note('K4', md5, f'{who}: аутентификация MD5 на {tname}')
            leak = [str(nw) for nw in o['networks'] if nw.subnet_of(ipaddress.ip_network('172.16.0.0/12'))]
            R.note('K4', not leak, f'{who}: сети ISP не объявлены в OSPF' + (f' (объявлены: {", ".join(leak)})' if leak else ''))
            extra_active = [i for i in o['no_passive'] if i != tname]
            if who == 'HQ-RTR' and extra_active:
                R.note('K4', False, f'HQ-RTR: активны лишние интерфейсы: {", ".join(extra_active)}')
            o_ok &= o['passive_default'] and tname in o['no_passive'] and md5 and not leak
        nb = (br.get('ospf') or '')
        full = len(re.findall(r'Full', nb))
        R.note('K4', full >= 2, f'BR-RTR: соседей OSPF в состоянии Full — {full} (нужно 2: HQ-RTR и BR-FW)')
        reach = cross and (ping('BR-SRV', str(hq_srv_ip.ip)) if hq_srv_ip else False)
        R.note('K4', reach, 'Сети офисов доступны друг другу (HQ-SRV ↔ BR-SRV)')
        R.set('K4', 2 if (o_ok and reach and full >= 2) else (1 if part else 0))
    else:
        reach = cross and hq_srv_ip and ping('BR-SRV', str(hq_srv_ip.ip))
        R.set('K4', 1 if reach else 0, manual=True)
        R.note('K4', bool(reach), 'Сети офисов доступны (MD5, пассивные интерфейсы — проверить вручную)')

    # ===================== K5: NAT офисов / Интернет =====================
    zones = {'HQ-SRV': ping('HQ-SRV', INET_IP), 'HQ-CLI': ping('HQ-CLI', INET_IP), 'BR-SRV': ping('BR-SRV', INET_IP)}
    web = {k: (conn.get(k) or {}).get('web', '') for k in zones}
    for k in zones:
        R.note('K5', zones[k], f'{k}: ping {INET_IP}; HTTP ya.ru → {web[k] or "нет ответа"}')
    hq_ok = zones['HQ-SRV'] and zones['HQ-CLI']
    R.set('K5', 2 if (hq_ok and zones['BR-SRV']) else (1 if (hq_ok or zones['BR-SRV']) else 0))

    # ===================== K6: DHCP =====================
    cli = data.get('HQ-CLI')
    if cli:
        dyn = [x for x in cli['_ips'] if x[2]]
        rs = cli.get('resolv', '')
        dns_ok = bool(hq_srv_ip) and re.search(rf'nameserver\s+{re.escape(str(hq_srv_ip.ip))}', rs) is not None
        dom_ok = re.search(rf'(search|domain)\s+.*\b{re.escape(DOMAIN)}\b', rs) is not None
        gw = re.search(r'default via (\S+)', cli.get('route', ''))
        gw_ok = bool(gw and dyn and ipaddress.ip_address(gw.group(1)) in dyn[0][1].network)
        R.note('K6', bool(dyn), f'HQ-CLI: адрес получен по DHCP ({dyn[0][1] if dyn else "нет"})')
        R.note('K6', gw_ok, f'HQ-CLI: шлюз {gw.group(1) if gw else "нет"}')
        R.note('K6', dns_ok, f'HQ-CLI: DNS-сервер = HQ-SRV ({hq_srv_ip.ip if hq_srv_ip else "?"})')
        R.note('K6', dom_ok, f'HQ-CLI: DNS-суффикс {DOMAIN}')
        excl = None
        if hqc:
            for pname, rng in hqc['ip_pools'].items():
                a, _, b = rng.partition('-')
                try:
                    lo, hi = ipaddress.ip_address(a), ipaddress.ip_address(b or a)
                    gws = [i.ip for d in hqc['ifaces'].values() for i in d['ip'] if dyn and i.ip in dyn[0][1].network]
                    excl = all(not (lo <= g <= hi) for g in gws)
                    R.note('K6', excl, f'HQ-RTR: пул {pname} {rng} не содержит адрес маршрутизатора')
                except ValueError:
                    pass
        params = [bool(dyn), gw_ok, dns_ok, dom_ok] + ([excl] if excl is not None else [])
        bad = params.count(False)
        R.set('K6', 0 if not dyn else (2 if bad == 0 else 1))
    else:
        R.set('K6', None, manual=True); R.note('K6', None, 'HQ-CLI: нет гостевого агента — проверить вручную')

    # ===================== K7: DNS =====================
    srv = data.get('HQ-SRV')
    if srv:
        active = srv.get('bind') == 'active'
        R.note('K7', active, f'HQ-SRV: служба bind — {srv.get("bind") or "не найдена"}')
        known = {
            'hq-srv': [hq_srv_ip.ip] if hq_srv_ip else [],
            'br-srv': [br_srv_ip.ip] if br_srv_ip else [],
            'hq-cli': [hq_cli_ip.ip] if hq_cli_ip else [],
            'hq-rtr': [i.ip for d in (hqc or {}).get('ifaces', {}).values() for i in d['ip']],
            'br-rtr': [i.ip for d in (brc or {}).get('ifaces', {}).values() for i in d['ip']],
            'docker': [x[1].ip for x in (isp or {}).get('_ips', []) if x[1].ip in ipaddress.ip_network(V['hq'])],
            'web': [x[1].ip for x in (isp or {}).get('_ips', []) if x[1].ip in ipaddress.ip_network(V['br'])],
        }
        errors = 0
        for name in ('hq-rtr', 'br-rtr', 'br-fw', 'hq-srv', 'hq-cli', 'br-srv', 'docker', 'web'):
            ans = [a for a in (srv.get(f'A {name}') or '').split() if re.match(r'\d+\.\d+\.\d+\.\d+$', a)]
            exp = known.get(name) or []
            if not ans:
                ok = False
            elif exp:
                ok = any(ipaddress.ip_address(a) in exp for a in ans)
            else:
                ok = True
            errors += (not ok)
            R.note('K7', ok, f'A {name}.{DOMAIN} → {", ".join(ans) or "нет"}' + (f' (ожидается {", ".join(map(str, exp))})' if exp and not ok else ''))
        ptr_bad = 0
        for nm, ip in (('hq-srv', hq_srv_ip), ('br-srv', br_srv_ip)):
            if ip:
                p = (srv.get(f'PTR {ip.ip}') or '').strip().rstrip('.')
                ok = p == f'{nm}.{DOMAIN}'
                ptr_bad += (not ok)
                R.note('K7', ok, f'PTR {ip.ip} → {p or "нет"}')
        fwd_ok = bool(srv.get('FWD'))
        R.note('K7', fwd_ok, 'Пересылка: имя ya.ru разрешается через HQ-SRV')
        if not active:
            R.set('K7', 0)
        else:
            total_err = errors + ptr_bad + (not fwd_ok)
            R.set('K7', 2 if total_err == 0 else (1 if total_err == 1 else 0))
    else:
        R.set('K7', None, manual=True); R.note('K7', None, 'HQ-SRV: нет гостевого агента — проверить вручную')

    # ===================== K8: подсети =====================
    nets = []
    if hq_srv_ip: nets.append(('HQ-SRV (≤32 адресов)', hq_srv_ip.network.prefixlen >= 27))
    if hq_cli_ip: nets.append(('HQ-CLI (≤16 адресов)', hq_cli_ip.network.prefixlen >= 28))
    if br_srv_ip: nets.append(('BR-SRV (≤16 адресов)', br_srv_ip.network.prefixlen >= 28))
    if hqc:
        mg = [i for port in hqc['ports'].values() for d in port.values()
              if re.search(rf'dot1q\s+{V["mgmt"]}\b', d.get('encap') or '') for i in hqc['ifaces'].get(d.get('iface'), {}).get('ip', [])]
        if mg: nets.append((f'VLAN {V["mgmt"]} (≤8 адресов)', mg[0].network.prefixlen >= 29))
    if brc:
        fw = [i for d in brc['ifaces'].values() if not d.get('tunnel') and d.get('nat') != 'outside' for i in d['ip']
              if not i.ip in ipaddress.ip_network(V['br'])]
        if fw: nets.append(('BR-RTR ↔ BR-FW (минимальная маска)', fw[0].network.prefixlen >= 30))
    for nm, ok in nets:
        R.note('K8', ok, nm)
    good = sum(ok for _, ok in nets)
    R.set('K8', 2 if nets and good == len(nets) and len(nets) >= 5 else (1 if good >= 2 else 0), manual=len(nets) < 5)

    # ===================== K9: IP, имена, время =====================
    dev_ok = 0
    for name in ('HQ-SRV', 'BR-SRV', 'HQ-CLI'):
        d = data.get(name)
        if d:
            hn = d.get('hostname', '')
            ok = hn == f'{FQDN[name]}.{DOMAIN}' and all(private(x[1]) for x in d['_ips']) and bool(d['_ips'])
            dev_ok += ok
            R.note('K9', ok, f'{name}: имя {hn or "?"}, адреса {", ".join(str(x[1]) for x in d["_ips"]) or "нет"}')
    for name, cfg in (('HQ-RTR', hqc), ('BR-RTR', brc)):
        if cfg:
            ok = cfg['hostname'] == FQDN[name] and cfg['domain'] == DOMAIN
            dev_ok += ok
            R.note('K9', ok, f'{name}: hostname {cfg["hostname"]}, домен {cfg["domain"]}')
    if isp:
        R.note('K9', True, f'ISP: имя {isp.get("hostname")}')
    fwd = data.get('BR-FW')
    if fwd:
        ok = fwd.get('hostname', '') == f'br-fw.{DOMAIN}' and bool(fwd['_ips'])
        dev_ok += ok
        R.note('K9', ok, f'BR-FW: имя {fwd.get("hostname")}, адреса {", ".join(str(x[1]) for x in fwd["_ips"]) or "нет"}')
    else:
        R.note('K9', None, 'BR-FW (Ideco): имя и адреса — проверить в веб-интерфейсе')
    checked = sum(1 for x in ('HQ-SRV', 'BR-SRV', 'HQ-CLI', 'BR-FW') if data.get(x)) + sum(1 for c in (hqc, brc) if c)
    R.set('K9', 2 if dev_ok == checked and checked >= 5 else (1 if dev_ok >= 2 else 0), manual=checked < 6)

    # ===================== K10: учётные записи =====================
    acc_bad = 0
    for name in ('HQ-SRV', 'BR-SRV'):
        d = data.get(name)
        if not d:
            R.note('K10', None, f'{name}: нет гостевого агента'); continue
        pw = d.get('passwd', '')
        uid = int(pw.split(':')[2]) if pw.count(':') >= 3 else None
        ok_uid = uid == V['uid']
        ok_sudo = d.get('sudo') == 'ok'
        pwc = d.get('pwcheck', 'unknown')
        R.note('K10', ok_uid, f'{name}: sshuser UID = {uid} (нужно {V["uid"]})')
        R.note('K10', ok_sudo, f'{name}: sudo без пароля')
        R.note('K10', True if pwc == 'ok' else (False if pwc == 'bad' else None), f'{name}: пароль P@ssw0rd — {pwc}')
        acc_bad += (not ok_uid) + (not ok_sudo) + (pwc == 'bad')
    for name, e in (('HQ-RTR', hq), ('BR-RTR', br)):
        cfg = (e or {}).get('cfg')
        if cfg:
            role = cfg['users'].get('net_admin', {}).get('role')
            ok = role == 'admin' and e.get('login') == 'net_admin'
            acc_bad += not ok
            R.note('K10', ok, f'{name}: net_admin, роль {role}, вход по паролю {"успешен" if e.get("login") == "net_admin" else "не выполнен"}')
        elif e and e.get('login') is False:
            acc_bad += 1
    R.set('K10', 2 if acc_bad == 0 else (1 if acc_bad == 1 else 0), manual=not (hqc and brc))

    # ===================== K11: SSH =====================
    ssh_bad = 0
    for name in ('HQ-SRV', 'BR-SRV'):
        d = data.get(name)
        if not d:
            R.note('K11', None, f'{name}: нет гостевого агента'); ssh_bad += 4; continue
        t = d.get('sshd', '').lower()
        port_ok = re.search(rf'^port {V["port"]}$', t, re.M) is not None and not re.search(r'^port 22$', t, re.M)
        allow_ok = re.search(r'^allowusers sshuser$', t, re.M) is not None
        tries_ok = re.search(r'^maxauthtries 2$', t, re.M) is not None
        banner_ok = BANNER.lower() in (d.get('banner', '').lower())
        for ok, what in ((port_ok, f'порт {V["port"]}'), (allow_ok, 'AllowUsers sshuser'), (tries_ok, 'MaxAuthTries 2'), (banner_ok, f'баннер «{BANNER}»')):
            R.note('K11', ok, f'{name}: {what}')
            ssh_bad += not ok
    for frm in ('HQ-SRV', 'BR-SRV'):
        out = (conn.get(frm) or {}).get('sshbanner', '')
        if out:
            R.note('K11', BANNER.lower() in out.lower(), f'{frm} → соседний сервер по SSH на порт {V["port"]}: {"баннер получен" if BANNER.lower() in out.lower() else out.splitlines()[0][:70]}')
    R.set('K11', 2 if ssh_bad == 0 else (1 if ssh_bad <= 2 else 0))

    # ===================== K12: часовой пояс =====================
    tz_alt = []
    for name in ('ISP', 'HQ-SRV', 'BR-SRV', 'HQ-CLI', 'BR-FW'):
        d = data.get(name)
        if d:
            ok = d.get('tz', '').endswith(ARGS.tz)
            tz_alt.append(ok)
            R.note('K12', ok, f'{name}: {d.get("tz")}')
    tz_rtr = []
    for name, cfg in (('HQ-RTR', hqc), ('BR-RTR', brc)):
        if cfg:
            if cfg.get('linux'):
                ok = (cfg['tz'] or '').endswith(ARGS.tz)
                R.note('K12', ok, f'{name}: {cfg["tz"]}')
            else:
                ok = (cfg['tz'] or '') == ARGS.tz_eco.lower()
                R.note('K12', ok, f'{name}: ntp timezone {cfg["tz"] or "не задан"}')
            tz_rtr.append(ok)
    if not data.get('BR-FW'):
        R.note('K12', None, 'BR-FW (Ideco): часовой пояс — проверить в веб-интерфейсе')
    # уровень 1 — серверы и клиент; уровень 2 — все устройства (ISP, маршрутизаторы, BR-FW)
    core = [data[x].get('tz', '').endswith(ARGS.tz) for x in ('HQ-SRV', 'BR-SRV', 'HQ-CLI') if data.get(x)]
    if tz_alt and all(tz_alt) and tz_rtr and all(tz_rtr) and len(core) == 3:
        R.set('K12', 2, manual=not data.get('BR-FW') or len(tz_rtr) < 2)
    elif core and all(core):
        R.set('K12', 1, manual=len(core) < 3)
    else:
        R.set('K12', 0, manual=not core)

    # ===================== K13: отчёт =====================
    R.set('K13', None, manual=True)
    R.note('K13', None, 'Отчёт ФамилияУчастникаЗадание1 — оценивает эксперт')
    return R, info


# ----------------------------------------------------------------------------------------------
# Вывод
# ----------------------------------------------------------------------------------------------
def points(lvl, mx):
    return None if lvl is None else round(mx * lvl / 2, 2)


def print_stand(R, info):
    V = VARIANTS[info['variant']]
    print(f"\n{C['b']}══ Стенд {info['stand']} ({info['pool']}), вариант {info['variant']}: VLAN {V['srv']}/{V['cli']}/{V['mgmt']}, "
          f"UID {V['uid']}, SSH {V['port']} ══{C['x']}")
    total, mx_auto = 0.0, 0
    for code, title, mx in CRITERIA:
        it = R.items[code]
        p = points(it['level'], mx)
        tag = (f"{C['ok']}{it['level']}/2{C['x']}" if it['level'] == 2 else
               f"{C['warn']}{it['level']}/2{C['x']}" if it['level'] == 1 else
               f"{C['bad']}0/2{C['x']}" if it['level'] == 0 else f"{C['warn']} — {C['x']}")
        man = f" {C['warn']}[ПРОВЕРИТЬ ВРУЧНУЮ]{C['x']}" if it['manual'] else ''
        print(f"{code:>4} {tag}  {title:<38} {('%.2f' % p) if p is not None else '  — '} из {mx}{man}")
        if p is not None:
            total += p
        if ARGS.verbose or (it['level'] is not None and it['level'] < 2):
            for ok, txt in it['notes']:
                mark = f"{C['ok']}✓{C['x']}" if ok else (f"{C['bad']}✗{C['x']}" if ok is False else f"{C['warn']}?{C['x']}")
                print(f"        {mark} {txt}")
    print(f"{C['b']}     Предварительно: {total:.2f} из 25{C['x']} {C['dim']}(K13 и пункты с пометкой подтверждает эксперт; "
          f"балл = макс. балл подкритерия × уровень / 2){C['x']}")
    return total


def main():
    global ARGS
    ap = argparse.ArgumentParser(description='Проверка Задания 1 ДЭ-2027 (варианты 1–4)')
    ap.add_argument('-n', '--stands', required=True, help='номера стендов: 1-10 или 1,3,5')
    ap.add_argument('--variant', type=int, choices=[1, 2, 3, 4], help='принудительно задать вариант для всех стендов')
    ap.add_argument('--pool', default=None, help='шаблон имени пула, например DE27_Z1_stand_{} (по умолчанию ищутся DE27_Z1_stand_N и DE27_Z1alt_stand_N)')
    ap.add_argument('--tz', default='Asia/Yekaterinburg', help='ожидаемый часовой пояс Linux')
    ap.add_argument('--tz-eco', default='utc+5', help='ожидаемый ntp timezone EcoRouter')
    ap.add_argument('--eco-fallback', default='admin:admin', help='запасная учётная запись EcoRouter login:password, если net_admin не создан (по умолчанию заводская admin:admin; пусто — отключить)')
    ap.add_argument('--out', default='/root/de27/results', help='каталог для CSV и журналов консоли')
    ap.add_argument('--save-console', action='store_true', help='сохранять журнал консоли EcoRouter (для отладки)')
    ap.add_argument('--serial-dir', default='/var/run/qemu-server', help=argparse.SUPPRESS)
    ap.add_argument('-v', '--verbose', action='store_true', help='подробный вывод по всем критериям')
    ARGS = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit('Запустите от root на узле Proxmox')

    stands = []
    for part in ARGS.stands.split(','):
        a, _, b = part.partition('-')
        stands += list(range(int(a), int(b or a) + 1))

    os.makedirs(ARGS.out, exist_ok=True)
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    csv_path = os.path.join(ARGS.out, f'z1_{stamp}.csv')
    rows = []
    for n in stands:
        print(f"{C['info']}Проверка стенда {n}…{C['x']}")
        R, info = check_stand(n, ARGS.variant)
        if not R:
            continue
        total = print_stand(R, info)
        row = {'Стенд': n, 'Вариант': info['variant']}
        for code, title, mx in CRITERIA:
            it = R.items[code]
            p = points(it['level'], mx)
            row[f'{code} уровень'] = '' if it['level'] is None else it['level']   # то, что эксперт ставит в таблицу
            row[f'{code} балл (из {mx})'] = '' if p is None else str(p).replace('.', ',')
            row[f'{code} вручную'] = 'да' if it['manual'] else ''
        row['Итого (предв.)'] = str(round(total, 2)).replace('.', ',')
        rows.append(row)
    if rows:
        with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter=';')
            w.writeheader(); w.writerows(rows)
        print(f"\n{C['ok']}Сводная таблица: {csv_path}{C['x']} (открывается в Excel)")


if __name__ == '__main__':
    main()
