import os
import binascii
def encode_number(n):
    b128_digits = []
    while n:
        b128_digits.insert(0, (n & 0x7f) | 0x80)
        n = n >> 7
    if not b128_digits:
        b128_digits.append(0)
    b128_digits[-1] &= 0x7f
    return b''.join([bytes((d,)) for d in b128_digits])

def encode_length(l):
    assert l >= 0
    if l < 0x80:
        return bytes((l,))
    s = ("%x" % l).encode()
    if len(s) % 2:
        s = b"0" + s
    s = binascii.unhexlify(s)
    llen = len(s)
    return bytes((0x80 | llen,)) + s

def orderlen(order):
    return (1+len("%x" % order))//2  # bytes

def string_to_number(string):
    return int(binascii.hexlify(string), 16)

def randrange(order):
    entropy = os.urandom
    assert order > 1
    bytes = orderlen(order)
    dont_try_forever = 10000  # gives about 2**-60 failures for worst case
    while dont_try_forever > 0:
        dont_try_forever -= 1
        candidate = string_to_number(entropy(bytes)) + 1
        if 1 <= candidate < order:
            return candidate
        continue
    raise RuntimeError("randrange() tried hard but gave up, either something"
                       " is very wrong or you got realllly unlucky. Order was"
                       " %x" % order)