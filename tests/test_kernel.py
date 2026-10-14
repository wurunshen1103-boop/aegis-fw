"""Opt-in only. Parent never invokes nft. Child must prove network namespace isolation."""
import os
import platform
import subprocess
import sys
import unittest
from pathlib import Path

@unittest.skipUnless(platform.system() == 'Linux' and os.environ.get('AEGIS_KERNEL_TESTS') == '1',
                     'requires explicit Linux isolated-kernel test opt-in')
class KernelTests(unittest.TestCase):
    def test_isolated_kernel_packet_path(self):
        self.assertEqual(os.geteuid(),0,'run this test in a disposable root-capable Linux VM')
        original=os.readlink('/proc/self/ns/net')
        result=subprocess.run(['/usr/bin/unshare','--net','--',sys.executable,
                               str(Path(__file__).with_name('kernel_probe.py')),original],
                              capture_output=True,text=True,timeout=45)
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
        self.assertIn('KERNEL_PASS',result.stdout)
