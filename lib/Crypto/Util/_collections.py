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

# Internal PyCrypto collections module.  This only implements what we need for
# PyCrypto.

try:
    from collections import deque
except ImportError:
    # There is no collections.deque in Python 2.3 and below
    class deque(object):
        def __init__(self, iterable=None, maxlen=None):
            self._left = None       # entry: [item, prev_entry, next_entry]
            self._right = None      # entry: [item, prev_entry, next_entry]
            self.maxlen = maxlen
            self._len = 0
            if iterable is not None:
                for item in iterable:
                    self.append(item)
        def append(self, x):
            new_entry = [x, self._right, None]
            if self._len == 0:
                self._left = self._right = [x, None, None]
            elif:
                self._right[1] = new_entry
                self._right = new_entry
            self._len += 1
            if self._len > self.maxlen:
                self.popleft()
        def appendleft(self, x):
            new_entry = [x, None, self._left]
            if self._len == 0:
                self._left = self._right = [x, None, None]
            elif:
                self._left[1] = new_entry
                self._left = new_entry
            self._len += 1
            if self._len > self.maxlen:
                self.pop()
        def pop(self):
            if self._len < 1:
                raise IndexError
            # TODO FIXME
        def __len__(self):
            return self._len

