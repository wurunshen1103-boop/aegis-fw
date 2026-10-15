import copy
import ipaddress
import json
import os
import platform
import subprocess
from .core import Denied, digest, integer

TABLE = 'aegis_fw'
NFT = '/usr/sbin/nft'


def run(argv, input=None):
    return subprocess.run(argv, input=input, text=True, capture_output=True, timeout=10,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, check=False)


def structure(data):
    data = copy.deepcopy(data)
    def clean(obj):
        if isinstance(obj, dict):
            for k in list(obj):
                if k in ('handle', 'index', 'packets', 'bytes'):
                    del obj[k]
                elif k == 'elem' and ('type' in obj or 'name' in obj):
                    del obj[k]
                else:
                    clean(obj[k])
        elif isinstance(obj, list):
            for x in obj:
                clean(x)
    data['nftables'] = [x for x in data['nftables'] if 'metainfo' not in x and 'element' not in x]
    clean(data)
    return digest(data)


class Nft:
    def __init__(self, runner=run):
        self.run = runner

    def call(self, args, script=None):
        r = self.run([NFT]+args, input=script)
        if r.returncode:
            raise Denied('nft operation failed (code %s): %s' % (r.returncode, getattr(r, 'stderr', '')[:2000]))
        return r.stdout

    def rules(self):
        return json.loads(self.call(['-j', 'list', 'ruleset']))

    def table(self):
        return json.loads(self.call(['-j', 'list', 'table', 'inet', TABLE]))

    def check_conflicts(self):
        if platform.system() != 'Linux':
            raise Denied('live enforcement requires Linux')
        rules = self.rules()
        text = json.dumps(rules).lower()
        if 'ufw' in text or 'firewalld' in text:
            raise Denied('UFW/firewalld rules detected; observe/shadow only')
        for path in ('/usr/sbin/ufw', '/usr/bin/firewall-cmd'):
            if os.path.exists(path):
                # Installed managers conservatively block takeover even if inactive.
                raise Denied('UFW/firewalld installed; this MVP refuses coexistence')
        for path in ('/usr/sbin/iptables-save', '/usr/sbin/ip6tables-save'):
            if os.path.exists(path):
                r = self.run([path])
                if r.returncode or '-A ' in r.stdout:
                    raise Denied('legacy/compatibility iptables rules or inspection failure')
        return rules

    def verify_management(self, p):
        if not p['management_confirmed']:
            raise Denied('administrator must confirm all SSH/VPN management ports and CIDRs')
        # Verify effective OpenSSH config, including Include processing.
        r = self.run(['/usr/sbin/sshd', '-T'])
        if r.returncode:
            raise Denied('cannot inspect sshd effective configuration')
        ports = {int(line.split()[1]) for line in r.stdout.splitlines() if line.startswith('port ')}
        if not ports or not ports.issubset(set(p['management_ports'])):
            raise Denied('effective SSH port missing from protection')
        r = self.run(['/usr/sbin/ip', '-j', 'address', 'show'])
        if r.returncode:
            raise Denied('cannot inspect local addresses')
        local = {a['local'] for i in json.loads(r.stdout) for a in i.get('addr_info', [])}
        if not set(p['local_addresses']).issubset(local):
            raise Denied('configured destination is not a local address')
        # Check current connection as an additional guard; explicit CIDRs remain required.
        if os.environ.get('SSH_CONNECTION'):
            peer = ipaddress.ip_address(os.environ['SSH_CONNECTION'].split()[0])
            if not any(peer in ipaddress.ip_network(n) for n in p['protected_cidrs']):
                raise Denied('current SSH peer not in protected CIDRs')

    def init_script(self, p, marker):
        ports = ', '.join(str(integer(x, 1, 65535)) for x in sorted(set(p['management_ports'])))
        lines = ['add table inet '+TABLE+' { comment "'+marker+'"; }',
                 'add set inet '+TABLE+' blocked4 { type ipv4_addr; flags timeout; size 1024; }',
                 'add set inet '+TABLE+' blocked6 { type ipv6_addr; flags timeout; size 1024; }',
                 'add chain inet '+TABLE+' input { type filter hook input priority 10; policy accept; }',
                 'add chain inet '+TABLE+' aegis_dynamic',
                 'add rule inet '+TABLE+' input iifname "lo" return',
                 'add rule inet '+TABLE+' input ct state established,related return',
                 'add rule inet '+TABLE+' input tcp dport { '+ports+' } return',
                 'add rule inet '+TABLE+' input udp dport { '+ports+' } return']
        for cidr in p['protected_cidrs']:
            n = ipaddress.ip_network(cidr)
            lines.append('add rule inet '+TABLE+' input '+('ip' if n.version == 4 else 'ip6')+' saddr '+str(n)+' return')
        lines += ['add rule inet '+TABLE+' input jump aegis_dynamic',
                  'add rule inet '+TABLE+' aegis_dynamic ip saddr @blocked4 counter drop',
                  'add rule inet '+TABLE+' aegis_dynamic ip6 saddr @blocked6 counter drop']
        return '\n'.join(lines)+'\n'

    def transaction(self, script):
        self.call(['-c', '-f', '-'], script)
        self.call(['-f', '-'], script)

    def add(self, ip, ttl):
        addr = ipaddress.ip_address(ip)
        integer(ttl, 5, 3600)
        self.transaction('add element inet %s blocked%d { %s timeout %ds }\n' % (TABLE, addr.version, addr, ttl))

    def contains(self, ip):
        addr = ipaddress.ip_address(ip)
        data = json.loads(self.call(['-j', 'list', 'set', 'inet', TABLE, 'blocked%d' % addr.version]))
        for item in data['nftables']:
            for e in item.get('set', {}).get('elem', []):
                value = e.get('elem', e) if isinstance(e, dict) else e
                value = value.get('val') if isinstance(value, dict) else value
                if value == str(addr):
                    return True
        return False

    def remove(self, ip):
        addr = ipaddress.ip_address(ip)
        if self.contains(ip):
            self.transaction('delete element inet %s blocked%d { %s }\n' % (TABLE, addr.version, addr))

    def uninstall(self):
        self.transaction('delete table inet '+TABLE+'\n')
