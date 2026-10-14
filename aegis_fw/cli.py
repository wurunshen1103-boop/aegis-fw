import argparse
import collections
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from .core import Denied, canonical, digest, eligible_events, normalize, proposal, validate_policy, validate_proposal
from .store import Store


def read_events(path):
    with open(path, 'rb') as f:
        for _ in range(20000):
            line = f.readline(65537)
            if not line:
                return
            if len(line) > 65536:
                raise Denied('event line exceeds 64 KiB')
            try:
                yield normalize(json.loads(line))
            except (ValueError, TypeError, KeyError):
                continue
        raise Denied('batch exceeds 20000 records; rotate/split input')


def groups(events):
    grouped = collections.defaultdict(dict)
    for e in events:
        key = (e['src_ip'], e['dest_ip'], e['dest_port'], e['proto'], e['signature_id'])
        grouped[key][e['id']] = e
    return [list(items.values())[-32:] for items in grouped.values()]


def main():
    ap = argparse.ArgumentParser(description='Aegis FW unprivileged observer and advisory model council')
    ap.add_argument('--policy', default='examples/policy.json')
    ap.add_argument('--db', default='aegis.sqlite')
    sub = ap.add_subparsers(dest='command', required=True)
    sub.add_parser('simulate')
    sub.add_parser('policy-id')
    sub.add_parser('audit')
    sub.add_parser('list')
    sub.add_parser('doctor')
    ing = sub.add_parser('ingest'); ing.add_argument('file')
    rev = sub.add_parser('review'); rev.add_argument('id'); rev.add_argument('--models', default='examples/models.json')
    exp = sub.add_parser('export'); exp.add_argument('id')
    args = ap.parse_args()
    try:
        p = validate_policy(json.loads(Path(args.policy).read_text()))
        if args.command == 'simulate':
            for flow in (1001, 1002):
                print(canonical({'event_type': 'alert', 'timestamp': datetime.now(timezone.utc).isoformat(),
                                 'flow_id': flow, 'src_ip': '8.8.4.4', 'dest_ip': p['local_addresses'][0],
                                 'dest_port': 443, 'proto': 'TCP',
                                 'alert': {'signature_id': p['allowed_signatures'][0], 'severity': 2,
                                           'signature': 'SIMULATION ONLY - never import into trusted live log'}}))
            return
        if args.command == 'policy-id':
            print(digest(p)); return
        if args.command == 'doctor':
            import platform
            print(json.dumps({'os': platform.system(), 'python': platform.python_version(),
                              'mode': p['mode'], 'nft_present': Path('/usr/sbin/nft').exists(),
                              'live_ready': False, 'next': 'root admin init performs live checks; no changes made'}, indent=2))
            return
        os.umask(0o077)
        store = Store(args.db)
        if args.command == 'ingest':
            accepted, held = [], 0
            for batch in groups(eligible_events(read_events(args.file), p)):
                try:
                    q = proposal(batch, p)
                    store.add(q)
                    row = store.db.execute('SELECT state FROM cases WHERE id=?', (q['id'],)).fetchone()
                    if p['mode'] != 'observe' and row[0] == 'observe':
                        store.move(q['id'], 'shadow')
                    accepted.append(q['id'])
                except Denied:
                    held += 1
            store.audit('ingest', accepted=len(accepted), held=held)
            print(json.dumps({'cases': accepted, 'held_groups': held, 'mode': p['mode'], 'firewall_changed': False}, indent=2))
        elif args.command == 'list':
            print(json.dumps([{'id': x[0], 'state': x[1]} for x in store.db.execute('SELECT id,state FROM cases')], indent=2))
        elif args.command == 'audit':
            print(json.dumps({'audit_head': store.verify_audit(), 'records': store.db.execute('SELECT count(*) FROM audit').fetchone()[0]}))
        else:
            row = store.db.execute('SELECT state,body FROM cases WHERE id=?', (args.id,)).fetchone()
            if not row:
                raise Denied('unknown case')
            q = json.loads(row[1]); validate_proposal(q, p)
            if args.command == 'export':
                if row[0] != 'propose':
                    raise Denied('review before export')
                print(canonical(q))
            else:
                if row[0] == 'observe':
                    raise Denied('observe mode does not propose; explicitly choose shadow/propose')
                from .models import Council
                cfg = json.loads(Path(args.models).read_text())
                result = Council(cfg, store).review(q, p['confidence_threshold'])
                if result['status'] in ('supported', 'disabled'):
                    if row[0] == 'shadow':
                        store.move(q['id'], 'propose')
                    result['manual_approval_required'] = True
                print(json.dumps(result, indent=2))
    except Exception as exc:
        print('DENIED: '+str(exc) if isinstance(exc, Denied) else 'ERROR: '+type(exc).__name__, file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
