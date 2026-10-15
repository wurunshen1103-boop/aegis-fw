import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from aegis_fw.firewall import Nft,structure
from aegis_fw.core import Denied
from test_core import policy

class FirewallTests(unittest.TestCase):
    def test_no_shell_fixed_nft_path(self):
        calls=[]
        def run(args,input=None):calls.append((args,input));return SimpleNamespace(returncode=0,stdout='')
        n=Nft(run);n.add('8.8.4.4',60)
        self.assertEqual(calls[0][0],['/usr/sbin/nft','-c','-f','-'])
        self.assertEqual(calls[1][0],['/usr/sbin/nft','-f','-'])
        self.assertNotIn('flush ruleset',calls[1][1])
    def test_timeout_range(self):
        with self.assertRaises(Denied):Nft().add('8.8.4.4',0)
    def test_injection_no_subprocess(self):
        with self.assertRaises(ValueError):Nft(lambda *a: self.fail('must not run')).add('8.8.4.4;sh',60)
    def test_protect_order(self):
        text=Nft().init_script(policy(),'test')
        self.assertLess(text.index('tcp dport'),text.index('jump "dynamic"'))
        self.assertIn('ct state established,related return',text)
        self.assertIn('policy accept',text);self.assertNotIn('flush',text)
    def test_manager_rules(self):
        def run(*a,**k):return SimpleNamespace(returncode=0,stdout=json.dumps({'nftables':[{'table':{'name':'firewalld'}}]}))
        with patch('platform.system',return_value='Linux'),self.assertRaises(Denied):Nft(run).check_conflicts()
    def test_nft_failure_closed(self):
        def run(*a,**k):return SimpleNamespace(returncode=1,stdout='')
        with self.assertRaises(Denied):Nft(run).rules()
    def test_realistic_timeout_element_read(self):
        data={'nftables':[{'set':{'elem':[{'elem':{'val':'8.8.4.4','timeout':60000,'expires':59000}}]}}]}
        n=Nft(lambda *a,**kw:SimpleNamespace(returncode=0,stdout=json.dumps(data)))
        self.assertTrue(n.contains('8.8.4.4'));self.assertFalse(n.contains('1.1.1.1'))
    def test_unknown_management_ports(self):
        with self.assertRaises(Denied):Nft().verify_management(policy())
    def test_sshd_nonstandard_port(self):
        p=policy();p['management_confirmed']=True
        n=Nft(lambda *a,**kw:SimpleNamespace(returncode=0,stdout='port 2222\n'))
        with self.assertRaises(Denied):n.verify_management(p)
