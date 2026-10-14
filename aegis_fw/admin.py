import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
from .core import Denied, canonical, digest, normalize, validate_policy
from .broker import Broker
from .firewall import Nft
from .store import Store

CONFIG = Path('/etc/aegis-fw/policy.json')
STATE_DIR = Path('/var/lib/aegis-fw')


def trusted(path, directory=False):
    path = Path(path)
    for p in (path,)+tuple(path.parents):
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Denied('root-owned, non-symlink, non-writable path required: '+str(p))
    st = path.stat()
    if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
        raise Denied('unexpected file type')
    return path


def evidence(path):
    trusted(path)
    # Bounded tail; old events outside tail are intentionally ineligible.
    with open(path, 'rb') as f:
        size = os.fstat(f.fileno()).st_size
        start = max(0, size-4*1024*1024)
        f.seek(start)
        if start:
            f.readline(65537)
        for _ in range(20000):
            line = f.readline(65537)
            if not line:
                break
            if len(line) > 65536:
                raise Denied('oversized trusted log record')
            try:
                yield normalize(json.loads(line))
            except (ValueError, KeyError, TypeError):
                continue


def main():
    parser = argparse.ArgumentParser(description='Root-only bounded nftables executor; fixed config paths')
    parser.add_argument('command', choices=['policy-id', 'init', 'apply', 'rollback', 'status', 'grant', 'revoke', 'auto', 'uninstall'])
    parser.add_argument('--confirm')
    parser.add_argument('--case')
    parser.add_argument('--signature', type=int)
    parser.add_argument('--seconds', type=int, default=300)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise Denied('administrator privileges required; no automatic privilege escalation')
        trusted(CONFIG)
        if CONFIG.stat().st_size > 65536:
            raise Denied('policy too large')
        policy = validate_policy(json.loads(CONFIG.read_text()))
        if args.command == 'policy-id':
            print(digest(policy))
            return
        trusted(STATE_DIR, True)
        lockpath = STATE_DIR/'lock'
        if lockpath.exists() or lockpath.is_symlink():
            trusted(lockpath)
        with open(lockpath, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            statepath = STATE_DIR/'state.json'
            if statepath.exists() or statepath.is_symlink():
                trusted(statepath)
            state = json.loads(statepath.read_text()) if statepath.exists() else {}
            def save(value):
                tmp = STATE_DIR/'state.tmp'
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(fd, 'w') as f:
                        f.write(canonical(value)); f.flush(); os.fsync(f.fileno())
                    os.replace(tmp, statepath)
                    d = os.open(STATE_DIR, os.O_RDONLY)
                    try:
                        os.fsync(d)
                    finally:
                        os.close(d)
                finally:
                    if tmp.exists():
                        tmp.unlink()
            for suffix in ('', '-wal', '-shm'):
                a = STATE_DIR/('audit.sqlite'+suffix)
                if a.exists() or a.is_symlink():
                    trusted(a)
            os.umask(0o077)
            store = Store(STATE_DIR/'audit.sqlite')
            store.verify_audit()
            broker = Broker(policy, Nft(), state, save, store.audit,
                            lambda: evidence(policy['evidence_path']))
            if args.command == 'init':
                result = broker.initialize(args.confirm)
            elif args.command == 'apply':
                data = sys.stdin.buffer.read(65537)
                if len(data) > 65536:
                    raise Denied('proposal too large')
                result = broker.apply(json.loads(data), args.confirm)
            elif args.command == 'rollback':
                result = broker.rollback(args.case)
            elif args.command == 'status':
                result = broker.reconcile()
            elif args.command == 'grant':
                body = {'signature_id': args.signature, 'seconds': args.seconds, 'policy_hash': digest(policy)}
                if not args.confirm:
                    result = {'grant': body, 'confirmation': digest(body)}
                else:
                    result = broker.grant(args.signature, args.seconds, args.confirm)
            elif args.command == 'auto':
                result = broker.automatic()
            elif args.command == 'revoke':
                broker.owned()
                store.audit('revoke', signature=args.signature)
                state['grants'].pop(str(args.signature), None)
                save(state)
                result = 'revoked; existing blocks retain TTL or use rollback'
            else:
                result = broker.uninstall(args.confirm)
            print(json.dumps(result, indent=2))
    except Exception as exc:
        if 'store' in locals():
            try:
                store.audit('denied', command=args.command, reason=str(exc) if isinstance(exc, Denied) else type(exc).__name__)
            except Exception:
                pass  # Original failure is still returned; never proceed with a mutation.
        print('DENIED: '+str(exc) if isinstance(exc, Denied) else 'ERROR: '+type(exc).__name__, file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
