"""Bounded journalctl JSON -> normalized SSH records. Never executes journalctl."""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from .core import Denied,canonical,integer,normalize
from .evidence import utc
from .ops_context import AUTH_FAILED,AUTH_ACCEPTED

PATTERN=re.compile(r'^(Failed|Accepted) (password|publickey|keyboard-interactive(?:/pam)?|none) for (?:invalid user )?\S{1,128} from ([0-9A-Fa-f:.]+) port ([0-9]{1,5})(?: ssh[12])?(?:[: ].*)?$')


def parse_record(raw,asset,port,hostname):
    if not isinstance(raw,dict) or raw.get('_HOSTNAME')!=hostname:return None,'wrong_host'
    comm=raw.get('_COMM');identifier=raw.get('SYSLOG_IDENTIFIER')
    if comm not in ('sshd','sshd-session','sshd-auth') and identifier not in ('sshd','sshd-session','sshd-auth'):
        return None,'not_sshd'
    message=raw.get('MESSAGE');stamp=raw.get('__REALTIME_TIMESTAMP')
    if not isinstance(message,str) or len(message)>8192 or '\n' in message or '\r' in message:
        return None,'invalid_message'
    if not isinstance(stamp,str) or not re.fullmatch(r'[0-9]{1,20}',stamp):return None,'invalid_timestamp'
    match=PATTERN.fullmatch(message)
    if not match:return None,'unsupported_ssh_message'
    try:
        source=str(ipaddress.ip_address(match[3]));integer(int(match[4]),1,65535)
        at=utc(int(stamp)/1000000)
    except (ValueError,OverflowError,OSError):return None,'invalid_network_or_time'
    # Use the original record digest for stable replay identity; no username/key material is exported.
    identity=hashlib.sha256(canonical(raw).encode()).hexdigest()
    e=normalize(dict(source='log-rule',src_ip=source,dest_ip=asset,dest_port=port,proto='tcp',
             signature_id=AUTH_FAILED if match[1]=='Failed' else AUTH_ACCEPTED,
             severity=3,timestamp=at,flow_id=str(int(identity[:16],16))))
    return e,'accepted'


def safe_file(p):
    if p.exists() or p.is_symlink():
        st=p.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o077:
            raise Denied('bridge files must be private regular files owned by this user')


def save(p,data):
    fd,name=tempfile.mkstemp(prefix='.bridge-',dir=p.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(canonical(data));f.flush();os.fsync(f.fileno())
        os.replace(name,p)
    finally:
        if os.path.exists(name):os.unlink(name)


def import_journal(input_path,bridge_dir,asset,port,hostname):
    if os.geteuid()==0:raise Denied('run the bridge as an ordinary user on an authorized log export')
    asset=str(ipaddress.ip_address(asset));integer(port,1,65535)
    if not isinstance(hostname,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}',hostname):raise Denied('explicit expected hostname required')
    source=Path(input_path).absolute()
    if source.is_symlink() or not source.is_file():raise Denied('input must be a regular file')
    source=source.resolve();directory=Path(bridge_dir).absolute()
    os.umask(0o077)
    if not directory.exists():directory.mkdir(mode=0o700)
    st=directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o077:raise Denied('bridge directory must be private')
    lock=directory/'lock';statefile=directory/'state.json';output=directory/'events.jsonl';provenance=directory/'provenance.jsonl'
    for p in (lock,statefile,output,provenance):safe_file(p)
    if source in (output,provenance,statefile,lock):raise Denied('input collides with a bridge output')
    with lock.open('a') as lockfile:
        fcntl.flock(lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
        binding={'source_path':str(source),'asset':asset,'port':port,'hostname':hostname}
        if statefile.exists():
            state=json.loads(statefile.read_text())
            if state.get('binding')!=binding:raise Denied('bridge is already bound to another source/host/service')
        else:
            if any(p.name!='lock' for p in directory.iterdir()):
                raise Denied('bridge directory is not empty and has no valid identity')
            if output.exists() or provenance.exists():raise Denied('unknown pre-existing bridge output; refusing adoption')
            state={'version':1,'binding':binding,'device':None,'inode':None,'offset':0}
            save(statefile,state)
        for p in (output,provenance):
            if p.exists() and p.stat().st_size:
                if p.stat().st_size>33554432:raise Denied('bridge size budget reached; archive explicitly')
                with p.open('rb') as f:
                    f.seek(-1,os.SEEK_END)
                    if f.read(1)!=b'\n':raise Denied('partial bridge output detected; preserve it for manual recovery')
        counters={};records=[];origins=[];warning=None;consumed=0
        fd=os.open(source,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):raise Denied('input is not a regular file')
            offset=state['offset']
            if (state['device'],state['inode'])!=(st.st_dev,st.st_ino):
                if state['inode'] is not None:warning='rotated; unread old-file data may be missing'
                offset=0
            elif st.st_size<offset:warning='truncated; coverage is incomplete';offset=0
            f.seek(offset)
            for _ in range(20000):
                start=f.tell();line=f.readline(65537)
                if not line:break
                if len(line)>65536:raise Denied('oversized journal line; no batch output committed')
                if not line.endswith(b'\n') or consumed+len(line)>4194304:f.seek(start);break
                consumed+=len(line)
                try:raw=json.loads(line);event,reason=parse_record(raw,asset,port,hostname)
                except (ValueError,TypeError,KeyError):event,reason=None,'invalid_json_record'
                counters[reason]=counters.get(reason,0)+1
                if event:
                    records.append(canonical(event)+'\n')
                    origins.append(canonical({'event_id':event['id'],'original_offset':start,'original_length':len(line),
                                              'original_line_sha256':hashlib.sha256(line).hexdigest()})+'\n')
            next_state=dict(state,device=st.st_dev,inode=st.st_ino,offset=f.tell())
            backlog=max(0,st.st_size-f.tell())
        # Output is durable before cursor advance. A crash can repeat records; downstream stable IDs deduplicate them.
        for p,lines in ((output,records),(provenance,origins)):
            with p.open('a') as f:f.writelines(lines);f.flush();os.fsync(f.fileno())
        save(statefile,next_state)
        result={'format':'journalctl-json-sshd','counts':counters,'normalized_records':len(records),
                'backlog_bytes':backlog,'continuity_warning':warning,'output':str(output),
                'usernames_retained':False,'raw_messages_retained':False,
                'identity_note':'flow_id is a stable log-record ID, not a verified network flow',
                'trust':'ordinary-user analysis import; not a privileged enforcement evidence source'}
        save(directory/'last-import.json',result)
        return result
