# Copyright (c) 2012 Ian C. Good
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

"""Module containing several |QueuePolicy| implementations for handling the
standard RFC headers.

"""

from __future__ import absolute_import

from dkim import sign, verify

from slimta.core import __version__ as VERSION
from . import QueuePolicy

__all__ = ['SignDkim']


class SignDkim(QueuePolicy):
    """Signs a message with dkim with specific  key, selector and domain

    """

    def __init__(self, key, selector, domain):
        self.key = key
        self.selector = selector
        self.domain = domain

    def apply(self, envelope):
        sig = sign(envelope.message, self.selector, self.domain, self.key)
        envelope.message = sig + envelope.message

class VerifyDkim(QueuePolicy):
    """Verifies a dkim message

    """

    def __init__(self):
        pass

    def apply(self, envelope):
        print envelope.message
        res = verify(envelope.message)
        envelope.headers['DKIM-Verify-Status'] = 'FAILED'



# vim:et:fdm=marker:sts=4:sw=4:ts=4
