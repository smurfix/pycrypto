# -*- coding: utf-8 -*-
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""CMAC: NIST SP 800-38B"""

# TODO FIXME
#import sys
#if sys.version_info < (2,6):
#    raise ImportError("You need at least Python 2.6 to import this module")

import sys

from Crypto.Util.strxor import strxor
from Crypto.Util.py3compat import *
from Crypto.Util._collections import deque

# TODO FIXME
#_16_CONST_ZERO = b("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
#_16_CONST_RB   = b("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87")
#_16_CONST_PAD  = b("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

class CMAC(object):
    """Class that implements CMAC - TODO"""

    # XXX - This class does an obscene amount of string copying.

    #: The block size of the underlying cipher.
    block_size = None

    #: The size of the authentication tag produced by the MAC.
    #: It matches the block size on the underlying
    #: cipher module used.
    digest_size = None

    def __init__(self, key, msg=None, ciphermod=None):
        if ciphermod is None:
            raise ValueError("ciphermod must be specified (try AES)")

        self.ciphermod = ciphermod
        self.block_size  = ciphermod.block_size
        self.digest_size = ciphermod.block_size

        self._CONST_ZERO = b("\0")*self.block_size                      # 0x000000..00
        self._CONST_RB   = b("\0")*(self.block_size-1) + b("\x87")      # 0x000000..87
        self._CONST_PAD  = b("\x80") + b("\0")*self.block_size          # 0x800000..00

        self._cipher = ciphermod.new(key, ciphermod.MODE_CBC, self._CONST_ZERO)
        self._k1, self._k2 = self._generate_subkey(key, ciphermod)
        #self._buf = array.array('B', [0] * ciphermod.block_size*2)  # bytearray is nicer, but not compatible    TODO FIXME  
        self._buf = deque()
        self._buflen = 0
        if msg is not None:
            self.update(msg)

    def _lshift(self, s):
        return long_to_bytes(bytes_to_long(s) << 1, len(s))[-len(s):]

    def _generate_subkey(self, k, ciphermod):
        l = ciphermod.new(k, ciphermod.MODE_ECB).encrypt(self._CONST_ZERO)
        if l < self._CONST_PAD:       # most-significant bit of l is equal to zero
            k1 = strxor(self._lshift(l), self._CONST_ZERO)
        else:
            k1 = strxor(self._lshift(l), self._CONST_RB)
        if k1 < self._CONST_PAD:       # most-significant bit of k1 is equal to zero
            k2 = strxor(self._lshift(k1), self._CONST_ZERO)
        else:
            k2 = strxor(self._lshift(k2), self._CONST_RB)
        return (k1, k2)

    def update(self, msg):
        # Add the incoming chunk to the buffer
        self._buf.append(msg)
        self._buflen += len(msg)

        # We need to keep the last block in the buffer, since it's handled
        # differently depending on its length.
        if self._buflen <= self.block_size:
            return

        # Drain excess chunks from the buffer
        drained = deque()
        drained_len = 0
        while self._buflen > self.block_size:
            chunk = self._buf.popleft()
            self._buflen -= len(chunk)
            drained.append(chunk)
            drained_len += len(chunk)

        # Split the last chunk, if necessary
        n, r = divmod(drained_len, self.block_size)
        if r > 0:
            chunk = drained.pop()
            drained_len -= len(chunk)
            a, b = buffer(chunk, 0, r), buffer(chunk, r)
            drained.append(a)
            drained_len += len(chunk)
            self._buf.appendleft(b)
            self._buflen += len(b)

        assert divmod(drained_len, self.block_size)[1] == 0
        self._cipher.encrypt(b("").join(drained))

    def digest(self):
        self._buf.append(self._CONST_PAD)
        try:
            if self._buflen == self.block_size:
                # Message length is a positive multiple of the block size
                subkey = self._k1
            else:
                subkey = self._k2
            last_block = b("").join(self._buf)
            self._cipher.copy()
        finally:
            self._buf.pop()

    def hexdigest(self):
        if sys.version_info[0] == 2:
            return b2a_hex(self.digest())
        else:
            return b2a_hex(self.digest()).decode()

def cmac(k, m):
    cipher = AES.new(k, AES.MODE_CBC, CONST_ZERO)
    n, r = divmod(len(m), AES.block_size)
    p = max(0, (n-1)*AES.block_size)
    if n > 0 and r == 0:
        # Message length is a positive multiple of the block size
        subkey = k1
    else:
        # Otherwise
        subkey = k2
    m1, m2 = m[:p], (m[p:] + CONST_PAD)[:AES.block_size]
    cipher.encrypt(m1)
    return cipher.encrypt(strxor(m2, subkey))

#: The block size of the underlying cipher.
block_size = None

#: The size of the authentication tag produced by the MAC.
#: It matches the block size on the underlying
#: cipher module used.
digest_size = None
