# -*- coding: utf-8 -*-
#
#  Cipher/blockalgo.py 
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
"""Module with definitions common to all block ciphers."""

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from Crypto.Util.py3compat import *

from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes

#: *Electronic Code Book (ECB)*.
#: This is the simplest encryption mode. Each of the plaintext blocks
#: is directly encrypted into a ciphertext block, independently of
#: any other block. This mode exposes frequency of symbols
#: in your plaintext. Other modes (e.g. *CBC*) should be used instead.
#:
#: See `NIST SP800-38A`_ , Section 6.1 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_ECB = 1

#: *Cipher-Block Chaining (CBC)*. Each of the ciphertext blocks depends
#: on the current and all previous plaintext blocks. An Initialization Vector
#: (*IV*) is required.
#:
#: The *IV* is a data block to be transmitted to the receiver.
#: The *IV* can be made public, but it must be authenticated by the receiver and
#: it should be picked randomly.
#:
#: See `NIST SP800-38A`_ , Section 6.2 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_CBC = 2

#: *Cipher FeedBack (CFB)*. This mode is similar to CBC, but it transforms
#: the underlying block cipher into a stream cipher. Plaintext and ciphertext
#: are processed in *segments* of **s** bits. The mode is therefore sometimes
#: labelled **s**-bit CFB. An Initialization Vector (*IV*) is required.
#:
#: When encrypting, each ciphertext segment contributes to the encryption of
#: the next plaintext segment.
#:
#: This *IV* is a data block to be transmitted to the receiver.
#: The *IV* can be made public, but it should be picked randomly.
#: Reusing the same *IV* for encryptions done with the same key lead to
#: catastrophic cryptographic failures.
#:
#: See `NIST SP800-38A`_ , Section 6.3 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_CFB = 3

#: This mode should not be used.
MODE_PGP = 4

#: *Output FeedBack (OFB)*. This mode is very similar to CBC, but it
#: transforms the underlying block cipher into a stream cipher.
#: The keystream is the iterated block encryption of an Initialization Vector (*IV*).
#:
#: The *IV* is a data block to be transmitted to the receiver.
#: The *IV* can be made public, but it should be picked randomly.
#:
#: Reusing the same *IV* for encryptions done with the same key lead to
#: catastrophic cryptograhic failures.
#:
#: See `NIST SP800-38A`_ , Section 6.4 .
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_OFB = 5

#: *CounTeR (CTR)*. This mode is very similar to ECB, in that
#: encryption of one block is done independently of all other blocks.
#: Unlike ECB, the block *position* contributes to the encryption and no
#: information leaks about symbol frequency.
#:
#: Each message block is associated to a *counter* which must be unique
#: across all messages that get encrypted with the same key (not just within
#: the same message). The counter is as big as the block size.
#:
#: Counters can be generated in several ways. The most straightword one is
#: to choose an *initial counter block* (which can be made public, similarly
#: to the *IV* for the other modes) and increment its lowest **m** bits by
#: one (modulo *2^m*) for each block. In most cases, **m** is chosen to be half
#: the block size.
#: 
#: Reusing the same *initial counter block* for encryptions done with the same
#: key lead to catastrophic cryptograhic failures.
#:
#: See `NIST SP800-38A`_ , Section 6.5 (for the mode) and Appendix B (for how
#: to manage the *initial counter block*).
#:
#: .. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
MODE_CTR = 6

#: *OpenPGP CFB*. This mode is a variant of CFB, and it is only used in PGP and OpenPGP_ applications.
#: An Initialization Vector (*IV*) is required.
#: 
#: Unlike CFB, the IV is not transmitted to the receiver. Instead, the *encrypted* IV is.
#: The IV is a random data block. Two of its bytes are duplicated to act as a checksum
#: for the correctness of the key. The encrypted IV is therefore 2 bytes longer than
#: the clean IV.
#:
#: .. _OpenPGP: http://tools.ietf.org/html/rfc4880
MODE_OPENPGP = 7

#: *Counter with CBC-MAC (CCM)*. This is an Authenticated Encryption with
#: Associated Data (`AEAD`_) mode. It provides both confidentiality and authenticity.
#: The header of the message may be left in the clear, if needed, and it will
#: still be subject to authentication. The decryption step tells the receiver
#: if the message comes from a source that really knowns the secret key.
#: Additionally, decryption detects if any part of the message - including the
#: header - has been modified or corrupted.
#:
#: This mode requires a nonce (*IV*). The nonce shall never repeat for two
#: different messages encrypted with the same key, but it does not need to be random. 
#: Note that you may not encrypt or decrypt more than ``256**(15-iv_size)`` bytes.
#:
#: This mode is only available for ciphers that operate on 128 bits blocks
#: (e.g. AES but not TDES).
#:
#: See `NIST SP800-38C`_ or RFC3610_ .
#:
#: .. _`NIST SP800-38C`: http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf
#: .. _RFC3610: https://tools.ietf.org/html/rfc3610
#: .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
MODE_CCM = 8

def _getParameter(name, index, targs, kwargs, default=None):
    """Find a parameter in tuple and dictionary arguments a function receives"""
    param = kwargs.get(name)
    if len(targs)>index:
        if param:
            raise ValueError("Parameter '%s' is specified twice" % name)
        param = targs[index]
    return param or default
    
class BlockAlgo:
    """Class modelling an abstract block cipher."""

    def __init__(self, factory, key, *args, **kwargs):
        self.mode = _getParameter('mode', 0, args, kwargs, default=MODE_ECB)
        self.block_size = factory.block_size
        self._factory = factory

        if self.mode == MODE_CCM:
            if self.block_size != 16:
                raise ValueError("CCM mode is only available for ciphers that operate on 128 bits blocks")

            self._mac_len = kwargs.get('mac_len', 8)        # t
            if self._mac_len not in (4,6,8,10,12,14,16):
                raise ValueError("Parameter 'mac_len' must be even and in the range 4..16")

            self.IV = _getParameter('IV', 1, args, kwargs)   # N
            if not (self.IV and 7<=len(self.IV)<=13):
                raise ValueError("Length of parameter 'IV' must be in the range 7..13 bytes")
 
            self._key = key
            self._msg_len = kwargs.get('msg_len', None)      # p
            self._assoc_len = kwargs.get('assoc_len', None)  # a
        
            self._assoc_buffer = b('')
            self._cipherCBC       = None
            self._done_assoc_data = False   # True when all associated data
                                            # has been processed
            # Try to start CCM
            self._start_ccm()
        
        elif self.mode == MODE_OPENPGP:
            self._start_PGP(factory, key, *args, **kwargs)
        else:
            self._cipher = factory.new(key, *args, **kwargs)
            self.IV = self._cipher.IV

    def _start_PGP(self, factory, key, *args, **kwargs):
        # OPENPGP mode. For details, see 13.9 in RCC4880.
        #
        # A few members are specifically created for this mode:
        #  - _encrypted_iv, set in this constructor
        #  - _done_first_block, set to True after the first encryption
        #  - _done_last_block, set to True after a partial block is processed
            
        self._done_first_block = False
        self._done_last_block = False
        self.IV = _getParameter('iv', 1, args, kwargs)
        if not self.IV:
            raise ValueError("MODE_OPENPGP requires an IV")
            
        # Instantiate a temporary cipher to process the IV
        IV_cipher = factory.new(key, MODE_CFB,
                b('\x00')*self.block_size,      # IV for CFB
                segment_size=self.block_size*8)
           
        # The cipher will be used for...
        if len(self.IV) == self.block_size:
            # ... encryption
            self._encrypted_IV = IV_cipher.encrypt(
                self.IV + self.IV[-2:] +        # Plaintext
                b('\x00')*(self.block_size-2)   # Padding
                )[:self.block_size+2]
        elif len(self.IV) == self.block_size+2:
            # ... decryption
            self._encrypted_IV = self.IV
            self.IV = IV_cipher.decrypt(self.IV +   # Ciphertext
                b('\x00')*(self.block_size-2)       # Padding
                )[:self.block_size+2]
            if self.IV[-2:] != self.IV[-4:-2]:
                raise ValueError("Failed integrity check for OPENPGP IV")
            self.IV = self.IV[:-2]
        else:
            raise ValueError("Length of IV must be %d or %d bytes for MODE_OPENPGP"
                % (self.block_size, self.block_size+2))

        # Instantiate the cipher for the real PGP data
        self._cipher = factory.new(key, MODE_CFB,
            self._encrypted_IV[-self.block_size:],
            segment_size=self.block_size*8)

    def _start_ccm(self, assoc_len=None, msg_len=None):
        # CCM mode. This method creates the 2 ciphers used for the MAC
        # (self._cipherCBC) and for the encryption/decryption (self._cipher).
        #
        # Member _assoc_buffer may already contain user data that needs to be
        # authenticated.

        if assoc_len is not None:
            self._assoc_len = assoc_len
        if msg_len is not None:
            self._msg_len = msg_len
        if None in (self._assoc_len, self._msg_len):
            return

        # q is the length of Q, the encoding of the message length
        q = 15 - len(self.IV)

        ## Compute B_0
        flags = 64*(self._assoc_len>0) + 8*divmod(self._mac_len-2,2)[0] + (q-1)
        b_0 = bchr(flags) + self.IV + long_to_bytes(self._msg_len, q)

        # Start CBC MAC with zero IV
        # Mind that self._assoc_buffer may already contain some data
        self._cipherCBC = self._factory.new(self._key, MODE_CBC, bchr(0)*16)
        assoc_len_encoded = b('')
        if self._assoc_len>0:
            if self._assoc_len<(2**16-2**8):
                enc_size = 2
            elif self._assoc_len<2L**32:
                assoc_len_encoded = b('\xFF\xFE')
                enc_size = 4
            else:
                assoc_len_encoded = b('\xFF\xFF')
                enc_size = 8
            assoc_len_encoded += long_to_bytes(self._assoc_len, enc_size)
        self._assoc_buffer = b_0 + assoc_len_encoded + self._assoc_buffer

        # Start CTR cipher
        flags = q-1
        prefix = bchr(flags)+self.IV
        ctr = Counter.new(128-len(prefix)*8, prefix, initial_value=0)
        self._cipher = self._factory.new(self._key, MODE_CTR, counter=ctr)
        self._s_0 = self._cipher.encrypt(bchr(0)*16) # Will XOR te CBC MAC

    def _pad_ccm(self):
        """Flush all user data that has not been authenticated yet, and pad
        with zeroes if necessary"""
        if len(self._assoc_buffer)>0:
            npad = (16-len(self._assoc_buffer)&15)&15
            self.update(bchr(0)*npad)

    def update(self, assoc_data):
        """Protect associated data

        When using an AEAD mode like CCM, and if there is any associated data,
        the caller has to invoke this function one or more times, before
        using `decrypt` or `encrypt`.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver is still able to detect any modification to it.

        If there is no authenticated data, this method must not be called.

        The caller may split the associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        :Parameters:
          assoc_data : byte string
            A piece of associated data. There are no restrictions on its size.
        """

        if self.mode == MODE_CCM:
            self._assoc_buffer += assoc_data
           
            if self._assoc_len is None:
                self._start_ccm(assoc_len=len(assoc_data))
            
            assoc_blocks = divmod(len(self._assoc_buffer), 16)[0]
            if assoc_blocks>0 and self._cipherCBC:
                self._t = self._cipherCBC.encrypt(self._assoc_buffer[:assoc_blocks*16])[-16:]
                self._assoc_buffer = self._assoc_buffer[assoc_blocks*16:]
            return
        raise ValueError("update() not supported by this mode of operation")
 
    def encrypt(self, plaintext):
        """Encrypt data with the key and the parameters set at initialization.
        
        The cipher object is stateful; encryption of a long block
        of data can be broken up in two or more calls to `encrypt()`.
        That is, the statement:
            
            >>> c.encrypt(a) + c.encrypt(b)

        is always equivalent to:

             >>> c.encrypt(a+b)

        That also means that you cannot reuse an object for encrypting
        or decrypting other data with the same key.

        This function does not perform any padding.
       
         - For `MODE_ECB`, `MODE_CBC`, and `MODE_OFB`, *plaintext* length
           (in bytes) must be a multiple of *block_size*.

         - For `MODE_CFB`, *plaintext* length (in bytes) must be a multiple
           of *segment_size*/8.

         - For `MODE_CTR` and `MODE_CCM`, *plaintext* can be of any length.

         - For `MODE_OPENPGP`, *plaintext* must be a multiple of *block_size*,
           unless it is the last chunk of the message.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
        :Return:
            the encrypted data, as a byte string. It is as long as
            *plaintext* with one exception: when encrypting the first message
            chunk with `MODE_OPENPGP`, the encypted IV is prepended to the
            returned ciphertext.
        """

        if self.mode == MODE_OPENPGP:
            padding_length = (self.block_size - len(plaintext) % self.block_size) % self.block_size
            if padding_length>0:
                # CFB mode requires ciphertext to have length multiple of block size,
                # but PGP mode allows the last block to be shorter
                if self._done_last_block:
                    raise ValueError("Only the last chunk is allowed to have length not multiple of %d bytes",
                        self.block_size)
                self._done_last_block = True
                padded = plaintext + b('\x00')*padding_length
                res = self._cipher.encrypt(padded)[:len(plaintext)]
            else:
                res = self._cipher.encrypt(plaintext)
            if not self._done_first_block:
                res = self._encrypted_IV + res
                self._done_first_block = True
            return res

        if self.mode == MODE_CCM:
            if self._assoc_len is None:
                self._start_ccm(assoc_len=0)
            if self._msg_len is None:
                self._start_ccm(msg_len=len(plaintext))
            if not self._done_assoc_data:
                self._pad_ccm()
                self._done_assoc_data = True
            self.update(plaintext)

        return self._cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        """Decrypt data with the key and the parameters set at initialization.
        
        The cipher object is stateful; decryption of a long block
        of data can be broken up in two or more calls to `decrypt()`.
        That is, the statement:
            
            >>> c.decrypt(a) + c.decrypt(b)

        is always equivalent to:

             >>> c.decrypt(a+b)

        That also means that you cannot reuse an object for encrypting
        or decrypting other data with the same key.

        This function does not perform any padding.
       
         - For `MODE_ECB`, `MODE_CBC`, and `MODE_OFB`, *ciphertext* length
           (in bytes) must be a multiple of *block_size*.

         - For `MODE_CFB`, *ciphertext* length (in bytes) must be a multiple
           of *segment_size*/8.

         - For `MODE_CTR` and `MODE_CCM`, *ciphertext* can be of any length.

         - For `MODE_OPENPGP`, *plaintext* must be a multiple of *block_size*,
           unless it is the last chunk of the message.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt.
        :Return: the decrypted data (byte string, as long as *ciphertext*).
        """

        if self.mode == MODE_OPENPGP:
            padding_length = (self.block_size - len(ciphertext) % self.block_size) % self.block_size
            if padding_length>0:
                # CFB mode requires ciphertext to have length multiple of block size,
                # but PGP mode allows the last block to be shorter
                if self._done_last_block:
                    raise ValueError("Only the last chunk is allowed to have length not multiple of %d bytes",
                        self.block_size)
                self._done_last_block = True
                padded = ciphertext + b('\x00')*padding_length
                res = self._cipher.decrypt(padded)[:len(ciphertext)]
            else:
                res = self._cipher.decrypt(ciphertext)
            return res

        if self.mode == MODE_CCM:
            if self._assoc_len is None:
                self._start_ccm(assoc_len=0)
            if self._msg_len is None:
                self._start_ccm(msg_len=len(ciphertext))
            if not self._done_assoc_data:
                self._pad_ccm()
                self._done_assoc_data = True

        pt = self._cipher.decrypt(ciphertext)

        if self.mode == MODE_CCM:
            self.update(pt)
 
        return pt

    def digest(self, mac_tag=None):
        """Compute the MAC tag in an AEAD mode.
       
        When using an AEAD mode like CCM, the caller has to invoke this
        function as last step.
        
        In case of an encryption operation, the caller has passed already all
        plaintext to the function `encrypt`. This method returns the tag that
        can be sent to the receiver.

        In case of a decryption operation, the caller has passed already all
        ciphertext to the function `decrypt`. This method takes the `tag`
        as received from the sender, and validates that the decrypted message
        is indeed valid (that is, that the key is correct) and it has not been
        tampered with while in transit.
        
        :Parameters:
          mac_tag : byte string
            In the decryption process, the MAC tag as received from the sender.
        :Raises ValueError:
          only after decrypting if the MAC does not match, meaning that
          the message has been tampered with or the key is incorrect.
        :Return: the MAC tag, as a byte string. It is computed over the associated
          data and the plaintext.
        """

        if self.mode == MODE_CCM:

            if self._assoc_len is None:
                self._start_ccm(assoc_len=0)
            if self._msg_len is None:
                self._start_ccm(msg_len=0)
            self._pad_ccm()

            u = strxor(self._t, self._s_0)[:self._mac_len]
            if mac_tag:
                res = 0
                # Constant-time comparison
                for x,y in zip(u, mac_tag):
                    res += bord(x) ^ bord(y)
                if res or len(mac_tag)!=self._mac_len:
                    raise ValueError("MAC check failed")
            return u

        raise ValueError("digest() not supported by this mode of operation")
 
