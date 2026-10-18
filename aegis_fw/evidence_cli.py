"""Read/collect/plan commands only; never calls a provider or the firewall executor."""
from datetime import datetime, timezone
import json
import os
import sqlite3
from pathlib import Path
import time
from .core import Denied, canonical, integer
from .evidence import EvidenceStore, scope, settings, timestamp, utc
from .investigation import brief, plan, save_checkpoint


def configure(parser):
    parser.add_argument('--store',default='evidence.sqlite',help='private evidence DB, separate from --db')
    parser.add_argument('--config',help='optional local evidence configuration JSON')
    sub=parser.add_subparsers(dest='evidence_command',required=True)
    collect=sub.add_parser('collect',help='incrementally collect a bounded JSONL batch, no model calls')
    collect.add_argument('file'); collect.add_argument('--sensor',required=True)
    opening=sub.add_parser('open',help='freeze an investigation scope and evidence watermark')
    opening.add_argument('--asset',required=True)
    opening.add_argument('--service',required=True,help='tcp:443 or udp:53')
    period=opening.add_mutually_exclusive_group(required=True)
    period.add_argument('--since',help='ISO timestamp with timezone')
    period.add_argument('--lookback-hours',type=int,help='bounded lookback ending at --until or now')
    opening.add_argument('--until',help='exclusive end; defaults to now')
    opening.add_argument('--source-ip')
    for name in ('refresh','timeline','windows','brief','plan','checkpoints'):
        cmd=sub.add_parser(name)
        cmd.add_argument('incident')
        if name in ('brief','plan'):
            cmd.add_argument('--output',help='create a new private JSON file; never overwrite')
        if name=='refresh':
            cmd.add_argument('--until',help='new exclusive endpoint; defaults to now')
        if name=='timeline':
            cmd.add_argument('--limit',type=int)
    series=sub.add_parser('series')
    series.add_argument('incident'); series.add_argument('--bucket-seconds',type=int,default=60)
    series.add_argument('--limit',type=int,default=200)
    show=sub.add_parser('show'); show.add_argument('evidence_id')
    checkpoint=sub.add_parser('checkpoint')
    checkpoint.add_argument('incident'); checkpoint.add_argument('file')
    sub.add_parser('status'); sub.add_parser('journal')
    demo=sub.add_parser('demo-events',help='emit historical synthetic EVE without network access')
    demo.add_argument('--asset',required=True)


def read_json(path,limit):
    with open(path,'rb') as f:
        raw=f.read(limit+1)
    if len(raw)>limit:
        raise Denied('JSON input exceeds byte limit')
    return json.loads(raw)


def run(args,policy):
    cfg=settings(read_json(args.config,65536) if args.config else None)
    command=args.evidence_command
    if command=='demo-events':
        import ipaddress
        asset=str(ipaddress.ip_address(args.asset))
        if asset not in policy['local_addresses']:
            raise Denied('demo destination must be a configured local address')
        now=time.time()
        # Deliberately old + recent observations. Synthetic only; no packets emitted.
        for i,age in enumerate((7*86400,86400,3600,300,30,2)):
            print(canonical(dict(event_type='alert',timestamp=utc(now-age),flow_id=10000+i,
                src_ip='8.8.4.4' if i%2==0 else '1.1.1.1',dest_ip=asset,dest_port=443,proto='TCP',
                alert=dict(signature_id=9900001,severity=2,
                           signature='SYNTHETIC HISTORY: never copy into a trusted enforcement log'))))
        return
    os.umask(0o077)
    store=EvidenceStore(args.store,policy['local_addresses'],cfg)
    try:
        if command=='collect':
            result=store.ingest(args.file,args.sensor)
        elif command=='open':
            end=args.until or utc(time.time())
            start=args.since
            if args.lookback_hours is not None:
                integer(args.lookback_hours,1,cfg['history_days']*24)
                start=utc(timestamp(end)-args.lookback_hours*3600)
            s=scope(store.assets,args.asset,args.service,start,end,cfg,args.source_ip)
            result=store.snapshot(s)
        elif command=='refresh':
            previous=store.incident(args.incident)
            updated=dict(previous['scope'],until=args.until or utc(time.time()))
            result=store.snapshot(updated,parent=args.incident)
        elif command=='timeline':
            result=store.records(store.incident(args.incident),args.limit)
        elif command=='windows':
            result=store.windows(store.incident(args.incident))
        elif command=='series':
            result=store.series(store.incident(args.incident),args.bucket_seconds,args.limit)
        elif command=='show':
            result=store.show(args.evidence_id)
        elif command=='brief':
            result=brief(store,args.incident)
        elif command=='plan':
            result=plan(store,brief(store,args.incident))
        elif command=='checkpoint':
            result=save_checkpoint(store,args.incident,read_json(args.file,16384))
        elif command=='checkpoints':
            store.incident(args.incident)
            result=[json.loads(r[0]) for r in store.db.execute(
                'SELECT body FROM checkpoints WHERE incident=? ORDER BY created DESC LIMIT 20',(args.incident,))]
        elif command=='journal':
            result=store.verify_journal()
        else:
            result=dict(schema_version=1,database_id=store.database_id,
                events=store.db.execute('SELECT count(*) FROM events').fetchone()[0],
                incidents=store.db.execute('SELECT count(*) FROM incidents').fetchone()[0],
                coverage=store.coverage(),retention='no automatic deletion; explicit archive/purge workflow is not implemented',
                network_calls=0,firewall_authority=False)
        if getattr(args,'output',None):
            # Export is an explicit user operation, with no silent replacement or symlink following.
            data=canonical(result)+'\n'
            fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w') as f:
                f.write(data); f.flush(); os.fsync(f.fileno())
            print(json.dumps(dict(output=str(Path(args.output).absolute()),bytes=len(data.encode())),indent=2))
        else:
            print(json.dumps(result,indent=2,ensure_ascii=False,allow_nan=False))
    except sqlite3.OperationalError as exc:
        if 'interrupted' in str(exc).lower():
            raise Denied('query execution budget exhausted; narrow the time/asset scope') from None
        raise
    finally:
        store.close()
