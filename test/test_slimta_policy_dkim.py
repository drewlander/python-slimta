
import unittest
import re

from assertions import *

from slimta.policy.slimdkim import SignDkim, VerifyDkim
from dkim import verify
from slimta.envelope import Envelope


key = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC2NipbyBTMY30gASaQ/6psG/LMtEZ2SLTN9BqLPeLttm7mHERy
NcKBZlAbpgw7tWTJSTO77ZXYbNLO7GzUVfBQfDKOsciTPuEk7DRbrUAw7UYmB6Ei
8d4lKLO8djGYQYw45Os9sRwcF5Vvk3epc3fCYek+5neAS8sp+Eley/BI4QIDAQAB
AoGAFt11M09ITN2vNfTvAgMTP73CGi4FKZK2HaIkMpTxhSL/h6DEdhCI9/P+2Xlc
z6FTpG6rL0oBI8eELLM+dObT4Q9/STYYTN3JnUC331xghBCqVjOvytPS9kIyrPg3
wYwuvtT6WyxgImo9NgQP1RQsInLni4l54bLDv++/IkMvuIECQQDaiJLC2EOW9iHe
8hELCfk+tlhrfjao6HgkLkBKIPdaho33iIK5kMg/769ulZ7vWGV6A+wXRHa9Gh/a
9WBg4kx/AkEA1XNs0wAoHsBVaD5N/NyNzvwqTz/bPRM+yXkPQdUOWhBIMlRINHP0
45zHE8RfD4o9D23WwxPPY7B1FmJf9vI6nwJAWrjN7JOpY5dkslBd4O5QCcfbZyyr
dm2jyqlkySFsbqljcHq8glrntxtDAi6dH5Hb9s6ACZzDine498ZcL3xi8wJAQxfd
BRXvhnr+XZ339Zt+F6m7wt1XlIMQIVQkL5VAxZ6IkwlbCOHKACGvkc8P8lqJhugH
sZnwfm1g4IBbmcvaEQJAGV95WmGAesgvixRrFINS+wNA51y2ySQRFOi5xg5rTnn/
8rXj1C+OqP6i+gHuUkHz2bcZIML5rnGKzEya/u7BVQ==
-----END RSA PRIVATE KEY-----"""

message="""Received: from localhost
Message-ID: <example@example.com>
Date: Mon, 01 Jan 2011 01:02:03 +0400
From: Test User <test@example.com>
To: somebody@example.com
Subject: Testing

             This is a test message.
"""

pubkey = """default._domainkey      IN      TXT     ( "v=DKIM1; k=rsa; "
          "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2NipbyBTMY30gASaQ/6psG/LMtEZ2SLTN9BqLPeLttm7mHERyNcKBZlAbpgw7tWTJSTO77ZXYbNLO7GzUVfBQfDKOsciTPuEk7DRbrUAw7UYmB6Ei8d4lKLO8djGYQYw45Os9sRwcF5Vvk3epc3fCYek+5neAS8sp+Eley/BI4QIDAQAB" )  ; ----- DKIM key default for test.com"""
class TestPolicyDkim(unittest.TestCase):

    def dnsfunc(self,domain):
        self.assertEqual('default._domainkey.test.com.', domain)
        return pubkey

    def test_sign_dkim(self):
        env = Envelope()
        env.parse('')
        env.timestamp = 1234567890
        env.message = message
        s = SignDkim(key, "default", "test.com")
        s.apply(env)
        self.assertTrue("DKIM-Signature" in env.message)




# vim:et:fdm=marker:sts=4:sw=4:ts=4
