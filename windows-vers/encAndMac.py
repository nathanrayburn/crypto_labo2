from base64 import b64decode

from Crypto.Cipher import AES

NONCE_LENGTH = 12
p = 340282366920938463463374607431768211507  # prime number


def bytesToInt(message):
    return int.from_bytes(message, "big")


def intToBytes(i):
    return int(i).to_bytes(16, "big")


# Compute the mac of message under key with nonce.
# It is similar to Poly1305
def mac(nonce, message, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    v = bytesToInt(cipher.encrypt(b"\xff" * 16))
    blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
    temp = 0
    for b in blocks:
        temp = (temp + bytesToInt(b) * v) % p
    temp = (temp + bytesToInt(cipher.encrypt(nonce + b"\x00" * (16 - NONCE_LENGTH)))) % p
    return intToBytes(temp)


# Encrypts the message under key with nonce.
# It is an improved CTR that exploits the power of prime numbers
def encrypt(nonce, message, key):
    ct = b""
    for i in range(len(message) // 16):
        cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
        keystream = cipher.encrypt(b"\x00" * 16)  # Way to obtain keystream: we XOR with 0
        temp = (bytesToInt(message[16 * i:16 * (i + 1)]) + bytesToInt(keystream)) % p
        ct += intToBytes(temp)
    return ct


# Encrypt and MAC with the fixed algorithm
def encryptAndMac(nonce, message, key):
    ct = encrypt(nonce, message, key)
    tag = mac(nonce, message, key)
    return (ct, tag)


def mod_inverse(x, mod):
    return pow(x, -1, mod)


m1 = b'ICRYInTheMorning'
nonce1 = b'LIrYgrQrcRZK/BnQ'
c1 = b'AdQMOX+adEHQnD3rw4Xjuw=='
tag1 = b'o5cixYgeS8CEifizc6cEuQ=='
nonce2 = b'gxRletwmC0f0HOGF'
c2 = b'Z4OCArnWY5p2DYGOpjmn1IeGeQ9n3mJHuFyni6+CotY='
tag2 = b'Tn9i1z9LalSEg8NQz1Uujw=='

# Decode c1 and c2 from base64
c1_decoded = b64decode(c1)
c2_decoded = b64decode(c2)

# Split m1, c1_decoded and c2_decoded into blocks
m1_blocks = [m1[i:i + 16] for i in range(0, len(m1), 16)]
c1_blocks = [c1_decoded[i:i + 16] for i in range(0, len(c1_decoded), 16)]
c2_blocks = [c2_decoded[i:i + 16] for i in range(0, len(c2_decoded), 16)]

first_block_c2 = c2_blocks[0]

sigma = (bytesToInt(c1_blocks[0]) - bytesToInt(m1_blocks[0])) % p

print("Sigma = ", sigma)

sumMAC = sum([bytesToInt(c1[i:i + 16]) for i in range(len(c1) // 16)]) % p
sumC2i = sum([bytesToInt(c2[i:i + 16]) for i in range(len(c2) // 16)]) % p

inverse_sumMAC = mod_inverse(sumMAC,p)

print("Inverse sum mac ", inverse_sumMAC)
print("Inverse * sum mac = ", (inverse_sumMAC * sumMAC) % p)

v = ((bytesToInt(tag1) - sigma) * inverse_sumMAC) % p

print("V value is :", v)
print("Sum C2 is : ", sumC2i)

m20 = (((p - bytesToInt(tag2)) + v * sumC2i + 2 * (p - bytesToInt(first_block_c2))) * mod_inverse(2, p)) % p

print("M2[0] = ", m20)
print("M2[0] = ", intToBytes(m20))
print("Complement : ", p-m20)
print("Complement : ", intToBytes(p-m20))



# need to inverse temp to find v with euclide_etendu since inverse mod
