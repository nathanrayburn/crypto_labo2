# Labo 2 Crypto
Author : Nathan Rayburn

## Mode of op

We can crack the messages, this is due because they both have the same **t** value as the first block. Since this variable is encrypted using AES with the same key, both texts have the same keystream. Even if the **t** value has changed between blocks. 

---
c1 and c2 are the ciphertexts, IV_1 and IV_2 are the initialization vectors. If t equals t2, it means that the same key (**t**) and IV were used for both encryptions.

$$
t = c1[16:32] \oplus IV_1
$$

$$
t2 = c2[16:32] \oplus IV_2
$$
---
Where c1_blocks and c2_blocks are the blocks of the ciphertexts, m1_blocks are the blocks of the plaintext of the first ciphertext.  

$$current\_stream = c2\_blocks[i] \oplus c1\_blocks[i]$$
$$pt = current\_stream \oplus m1\_blocks[i]$$

The decrypted blocks are then concatenated together to form the decrypted message. This is represented as:  
msg = concatenate(msg, pt)
where msg is the decrypted message and pt is the decrypted block.
The final concatenated message is our decrypted message.

## Enc And Mac

The security issue concerning the implementation of this system is that our counter is not working. In the code, the counter is initialized in a loop, which is reset after each iteration. This makes the CTR useless. We also have our keystream that is encrypted with 16 bytes of zeros. This error provides every block of 16 bytes with the same keystream since there is no counter.

By using the math formulas, we can achieve finding **V** which is a constant used for both texts and will be usefull to find later our plain text message. We have an other unknown variable to find which is sigma. Sigma is going to be our key stream.

We can find sigma by substracting our plain text block from the ciphered text block. This has to be from the same message. We can chose any block, first, second, third... etc... since they all have the same key stream due to the CTR being useless.

$$
\sigma = \left( (c1\_blocks[0]) - (m1\_blocks[0]) \right) \mod p
$$

The second step is to isolate **V** like so and plug in the sigma we have found previously.


Given formula :
$$
\sigma = \left( \text{tag1} - \sum_{i=0}^{n} m_i \cdot v \right) \mod p
$$
**V** Isolated :
$$
v = \left( \left((\text{tag1}) - \sigma\right) \times \text{{mod\_inverse}}({\sum_{i=0}^{n} m_i}, p) \right) \mod p
$$


---
The next step is to find sigma for the second message. 

We can take our initial formula and isolate sigma.


$$
\text{{MAC = }} \sum_{i=0}^{n} m_i \cdot v + \sigma \mod p
$$

Here is sigma isolated.

$$
\sigma = \left( \text{MAC} - \sum_{i=0}^{n} m_i \cdot v \right) \mod p
$$
---

The issue is that we don't have mi, we must find an equivalent for it. We can do so by using a formula that we have used previously.

$$
\sigma = \left( c1\_blocks[0] - m1\_blocks[0] \right) \mod p
$$
By isolating our message we get this.
$$
m1\_blocks[0] = \left( c1\_blocks[0] - \sigma \right) \mod p
$$

Now we can generalize it for the sum of mi.

$$
\sum_{i=0}^{n} m_i = \left( \sum_{i=0}^{n} c_i - \sigma \right) \mod p
$$

$$
=> \sum_{i=0}^{n} m_i = \left( \sum_{i=0}^{n} c_i  \right) - n\cdot\sigma \mod p
$$

---

We can finally replace the sum of mi in our initial formala and isolate sigma.

$$
\text{sumC2} = \left( \sum_{i=0}^{\text{len}(c2\_blocks)-1} \text(c2\_blocks[i]) \right) \mod p
$$

$$
\sigma_2 = \left( \left((\text{{tag2}}) - v \times \text{{sumC2}}\right) \times \text{{mod\_inverse}}(1 - v \times n, p) \right) \mod p
$$

We have finally found the sigma for the other message, this means we are ready to decrypt.
$$
\text{{plaintext}} = \bigoplus_{c2_{block} \in c2\_blocks} \left( \left( (c2_{block}[i]) - \sigma_2 \right) \mod p \right)
$$

The result of the decrypted message : 

```bash
b'Congrats! The secret is cozening'
```
## HMac

The issue of this implementation is that we can forge our own MAC and have a valide MAC for a key we don't know the value of. Since we know the MAC of the last block of the message, we can forge a new message by simply adding a new block to the initial message. 

[![](https://mermaid.ink/img/pako:eNpNkMFqwzAQRH9l2XNC7i4U7NjQQ6GQXApRKKq1rYRtychSWhPl37OuklCdpNmZx6zO2DpFWOC3l6OG192TsMCnPAjsaN6Mnk7GxQm0nLTAI6zXz-kkewgOyLZ-HkOCis1ls__ooNlWbMqILaufvWu7gznek4xke55XiwLpRiGVoObEyyNf_82bW5_8YMP7226hZbnJDEu_AbhVpH-94McEnaAUFlc4kB-kUbzoeUkKDJoGEljwVUnfCRT2wj4Zg9vPtsUi-EgrjKOSgWoj-X8GLL5kP9HlCmdBYGA?type=png)](https://mermaid.live/edit#pako:eNpNkMFqwzAQRH9l2XNC7i4U7NjQQ6GQXApRKKq1rYRtychSWhPl37OuklCdpNmZx6zO2DpFWOC3l6OG192TsMCnPAjsaN6Mnk7GxQm0nLTAI6zXz-kkewgOyLZ-HkOCis1ls__ooNlWbMqILaufvWu7gznek4xke55XiwLpRiGVoObEyyNf_82bW5_8YMP7226hZbnJDEu_AbhVpH-94McEnaAUFlc4kB-kUbzoeUkKDJoGEljwVUnfCRT2wj4Zg9vPtsUi-EgrjKOSgWoj-X8GLL5kP9HlCmdBYGA)

---

We first need to pad out the last block of the initial message and then the new block we want to add, we can add any value we want and then calculate the final MAC of the new message without even knowing the key.

**m**            is our original message that we want to forge.

**previous_mac** is the tag that was generated with the original message.

**new_amount** is the amount we want to add to our transaction, in this case this is the value we want to forge into our message.

```python
def verify(message, key, tag):
    return mac(message, key) == tag

def create_new_message(m, previous_mac, new_amount):
    m = pad(m) # pad the last block
    m += new_amount # add amount to create a new block
    mPrime = m # retrieve forged message
    m = pad(m) # pad the block to calculate the new tag
    blocks = [m[i:i + 16] for i in range(0, len(m), 16)] # transform into blocks
    # calculate the new mac for the last new block that has been added
    h = previous_mac
    h = strxor(AES.new(blocks[-1], AES.MODE_ECB).encrypt(h), h)
    return h, mPrime
```
So now we have **mPrime** that will be able to validate the verify function with our new tag without knowing the value of the **key**.

---