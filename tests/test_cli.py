import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_core import ROOT

class CLITests(unittest.TestCase):
    def test_simulate_ingest_review_export(self):
        with tempfile.TemporaryDirectory() as d:
            def cli(*args):
                r=subprocess.run([sys.executable,'-m','aegis_fw','--db',d+'/db',*args],cwd=ROOT,
                                 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr);return r.stdout
            raw=cli('simulate');Path(d+'/events').write_text(raw)
            result=json.loads(cli('ingest',d+'/events'));self.assertFalse(result['firewall_changed'])
            case=result['cases'][0];self.assertEqual(json.loads(cli('list'))[0]['state'],'shadow')
            review=json.loads(cli('review',case));self.assertEqual(review['status'],'disabled')
            self.assertEqual(json.loads(cli('export',case))['id'],case)
            self.assertGreater(json.loads(cli('audit'))['records'],0)
            self.assertEqual(len(json.loads(cli('ingest',d+'/events'))['cases']),1)
