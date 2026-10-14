"""Real packets, two anonymous namespaces; never create named host namespaces."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

if sys.platform != 'linux' or len(sys.argv)!=2 or os.readlink('/proc/self/ns/net') == sys.argv[1]:
    raise SystemExit('REFUSE: not isolated from invoking network namespace')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from aegis_fw.firewall import Nft,structure
import json


def run(*args):
    return subprocess.run(list(args),check=True,capture_output=True,text=True).stdout

def ip(*args): return run('/usr/sbin/ip',*args)

def server(addr,port,family=socket.AF_INET):
    s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((addr,port));s.listen(20)
    def worker():
        while True:
            c,_=s.accept()
            def echo(c):
                with c:
                    while True:
                        data=c.recv(100)
                        if not data:break
                        c.sendall(data)
            threading.Thread(target=echo,args=(c,),daemon=True).start()
    threading.Thread(target=worker,daemon=True).start()
    return s

peer=subprocess.Popen(['/usr/bin/unshare','--net','--','/usr/bin/sleep','40'])
servers=[]
try:
    for _ in range(100):
        if os.readlink('/proc/%d/ns/net'%peer.pid)!=os.readlink('/proc/self/ns/net'):break
        time.sleep(.01)
    else:raise AssertionError('peer namespace not ready')
    def peer_run(*args):return run('/usr/bin/nsenter','-t',str(peer.pid),'-n','--',*args)
    ip('link','set','lo','up');ip('link','add','af-host','type','veth','peer','name','af-peer')
    ip('link','set','af-peer','netns',str(peer.pid));ip('link','set','af-host','up')
    peer_run('/usr/sbin/ip','link','set','lo','up');peer_run('/usr/sbin/ip','link','set','af-peer','up')
    ip('addr','add','192.0.2.10/24','dev','af-host')
    peer_run('/usr/sbin/ip','addr','add','8.8.4.4/32','dev','af-peer')
    ip('route','add','8.8.4.4/32','dev','af-host')
    peer_run('/usr/sbin/ip','route','add','192.0.2.10/32','dev','af-peer')
    ip('-6','addr','add','2001:db8::10/64','dev','af-host','nodad')
    peer_run('/usr/sbin/ip','-6','addr','add','2606:4700:4700::1111/128','dev','af-peer','nodad')
    ip('-6','route','add','2606:4700:4700::1111/128','dev','af-host')
    peer_run('/usr/sbin/ip','-6','route','add','2001:db8::10/128','dev','af-peer')
    p=json.loads((Path(__file__).resolve().parents[1]/'examples/policy.json').read_text());p['management_ports']=[22,2222]
    n=Nft();n.transaction('add table inet existing\nadd chain inet existing input { type filter hook input priority 0; policy accept; }\nadd rule inet existing input tcp dport 19090 drop\n')
    before=structure(json.loads(n.call(['-j','list','table','inet','existing'])))
    n.transaction(n.init_script(p,'aegis-test'));fp=structure(n.table())
    for port in (18080,2222,19090):servers.append(server('192.0.2.10',port))
    servers.append(server('2001:db8::10',18080,socket.AF_INET6))
    def connect(addr,port,expected=True):
        code='import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),.6); s.sendall(b"x"); assert s.recv(1)==b"x"'
        r=subprocess.run(['/usr/bin/nsenter','-t',str(peer.pid),'-n','--',sys.executable,'-c',code,addr,str(port)],capture_output=True)
        assert (r.returncode==0)==expected,(addr,port,r.stderr)
    connect('192.0.2.10',18080);connect('2001:db8::10',18080);connect('192.0.2.10',19090,False)
    # A pre-existing stream remains usable after blocking its source.
    code='import socket,sys; s=socket.create_connection(("192.0.2.10",18080),2); print("ready",flush=True); sys.stdin.readline(); s.sendall(b"x"); assert s.recv(1)==b"x"'
    stream=subprocess.Popen(['/usr/bin/nsenter','-t',str(peer.pid),'-n','--',sys.executable,'-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    assert stream.stdout.readline().strip()=='ready'
    n.add('8.8.4.4',5);n.add('2606:4700:4700::1111',5)
    assert n.contains('8.8.4.4') and n.contains('2606:4700:4700::1111')
    assert structure(n.table())==fp
    stream.communicate('\n',timeout=3);assert stream.returncode==0
    connect('192.0.2.10',18080,False);connect('2001:db8::10',18080,False)
    connect('192.0.2.10',2222)
    time.sleep(5.2)
    assert not n.contains('8.8.4.4');connect('192.0.2.10',18080)
    assert not n.contains('2606:4700:4700::1111');connect('2001:db8::10',18080)
    n.add('8.8.4.4',30);n.remove('8.8.4.4');connect('192.0.2.10',18080)
    n.uninstall();assert structure(json.loads(n.call(['-j','list','table','inet','existing'])))==before
    connect('192.0.2.10',19090,False)
    print('KERNEL_PASS: IPv4 IPv6 TTL SSH-port established-flow rollback unrelated-table preservation')
finally:
    peer.terminate();peer.wait(timeout=3)
    for s in servers:s.close()
