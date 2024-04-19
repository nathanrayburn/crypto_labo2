from Crypto.Cipher import AES


NONCE_LENGTH = 12
p = 340282366920938463463374607431768211507 #prime number


def bytesToInt(message):
    return int.from_bytes(message, "big")

def intToBytes(i):
    return int(i).to_bytes(16, "big")

#Compute the mac of message under key with nonce. 
#It is similar to Poly1305
def mac(nonce, message, key):
    cipher = AES.new(key, mode = AES.MODE_ECB)
    v = bytesToInt(cipher.encrypt(b"\xff"*16))
    blocks = [message[i:i+16] for i in range(0,len(message),16)]
    temp = 0
    for b in blocks:
        temp = (temp + bytesToInt(b)*v) % p
    temp = (temp + bytesToInt(cipher.encrypt(nonce + b"\x00"*(16-NONCE_LENGTH)))) % p
    return intToBytes(temp)
    
#Encrypts the message under key with nonce. 
#It is an improved CTR that exploits the power of prime numbers
def encrypt(nonce, message, key):
    ct = b""
    for i in range(len(message)//16):
        cipher = AES.new(key, mode = AES.MODE_CTR, nonce = nonce)
        keystream = cipher.encrypt(b"\x00"*16) #Way to obtain keystream: we XOR with 0
        temp = (bytesToInt(message[16*i:16*(i+1)]) + bytesToInt(keystream)) % p
        ct += intToBytes(temp)
    return ct


#Encrypt and MAC with the fixed algorithm
def encryptAndMac(nonce, message, key):
    ct = encrypt(nonce, message, key)
    tag = mac(nonce, message, key)
    return (ct, tag)

def euclide_etendu(a,b):
    if(a<b):
        temp = a
        a = b
        b = temp

    v1 = [a,1,0]
    v2 = [b,0,1]

    while(v2[0] != 0):
        temp = v2.copy()
        f = v1[0]//v2[0]

        v2[1] = v1[1] + v2[1] * -f
        v2[2] = v1[2] + v2[2] * -f
        v2[0] = v1[0] % v2[0]

        v1 = temp.copy()
    return v1

m1 = b'ICRYInTheMorning'
nonce1 = b'LIrYgrQrcRZK/BnQ'
c1 = b'AdQMOX+adEHQnD3rw4Xjuw=='
tag1 = b'o5cixYgeS8CEifizc6cEuQ=='
nonce2 = b'gxRletwmC0f0HOGF'
c2 = b'Z4OCArnWY5p2DYGOpjmn1IeGeQ9n3mJHuFyni6+CotY='
tag2 = b'Tn9i1z9LalSEg8NQz1Uujw=='

sigma = (c1[0] - m1[0]) % p
sumMAC = sum([bytesToInt(m1[i:i+16]) for i in range(len(c1) // 16)]) % p


v = ((bytesToInt(tag1) - sigma) * euclide_etendu(p, sumMAC)[2]) % p
print(v)
# need to inverse temp to find v with euclide_etendu since inverse mod
