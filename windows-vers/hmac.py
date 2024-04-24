from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Util.strxor import strxor
import sys


def pad(m):
    m += b"\x80"
    while len(m) % 16 != 0:
        m+= b"\x00"
    return m

def h(m, k):
    m = pad(m)
    blocks = [m[i:i + 16] for i in range(0, len(m), 16)]
    h = k
    for i in range(len(blocks)):
        h = strxor(AES.new(blocks[i], AES.MODE_ECB).encrypt(h), h)
    return h

def mac(message, key):
    return h(message, key)
def verify(message, key, tag):
    return mac(message, key) == tag
def ex():
    k = Random.get_random_bytes(16)
    m = b"Sender: Alexandre Duc; Destination account 12-1234-12. Amount CHF123"
    m2 = b"Sender: Alexandre Duc; Destination account 12-1234-12. Amount CHF123\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00800"
    mc =  mac(m, k)
    m2_blocks = [m2[i:i + 16] for i in range(0, len(m2), 16)]

    newMac = h(m2_blocks[-1], mc)

    print("m = %s" % m)
    print("mac = %s" % mc)
    print("verify = %s" % verify(m, k, mc))
    print("verify = %s" % verify(m2, k, newMac))
    pretty_print(newMac)
#m has to be a bytestring
def pretty_print(m):
    print(m.decode("UTF-8", errors="ignore"))

ex()