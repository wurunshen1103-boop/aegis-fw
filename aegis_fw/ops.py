"""Pilot CLI for Linux operations teams: SSH import, context, evidence-first reports."""
import argparse
import json
import os
from pathlib import Path
from .core import Denied,canonical,validate_policy
from .evidence import EvidenceStore,settings
from .investigation import brief
from .journal_bridge import import_journal
from .ops_context import enrich_packet,load_context
from .ops_report import build_report,markdown


def read_json(path,cap=1048576):
    with open(path,'rb') as f:data=f.read(cap+1)
    if len(data)>cap:raise Denied('input exceeds byte limit')
    return json.loads(data)


def main():
    p=argparse.ArgumentParser(description='Read-only Linux operations pilot tools; never controls a firewall')
    p.add_argument('--policy',required=True);p.add_argument('--config')
    sub=p.add_subparsers(dest='command',required=True)
    j=sub.add_parser('journal',help='convert a bounded local journalctl JSON batch, incrementally')
    j.add_argument('--input',required=True);j.add_argument('--bridge',required=True)
    j.add_argument('--asset',required=True);j.add_argument('--port',type=int,default=22)
    j.add_argument('--hostname',required=True)
    for name in ('context','report'):
        c=sub.add_parser(name);c.add_argument('--store',required=True);c.add_argument('--incident',required=True)
        c.add_argument('--ops-context',required=True);c.add_argument('--output',required=True)
        if name=='report':c.add_argument('--run-state');c.add_argument('--format',choices=['json','markdown'],default='markdown')
    args=p.parse_args()
    try:
        if os.geteuid()==0:raise Denied('pilot commands require an ordinary user')
        os.umask(0o077)
        policy=validate_policy(read_json(args.policy,65536))
        if args.command=='journal':
            if args.asset not in policy['local_addresses']:raise Denied('asset is outside host policy')
            print(json.dumps(import_journal(args.input,args.bridge,args.asset,args.port,args.hostname),ensure_ascii=False,indent=2));return
        cfg=settings(read_json(args.config,65536) if args.config else None)
        context=load_context(args.ops_context)
        store=EvidenceStore(args.store,policy['local_addresses'],cfg)
        try:packet=enrich_packet(store,brief(store,args.incident),context)
        finally:store.close()
        if args.command=='context':text=canonical(packet)+'\n'
        else:
            state=read_json(args.run_state,4194304) if args.run_state else None
            report=build_report(packet,state)
            text=markdown(report) if args.format=='markdown' else canonical(report)+'\n'
        fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:f.write(text)
        print(json.dumps({'output':str(Path(args.output).absolute()),'cloud_calls':0,'firewall_operations':0}))
    except Exception as exc:
        print('DENIED: '+str(exc) if isinstance(exc,Denied) else 'ERROR: '+type(exc).__name__)
        raise SystemExit(2)
if __name__=='__main__':main()
