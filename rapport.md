# Labo 2 Crypto
Author : Nathan Rayburn

## Mode of op



## Enc And Mac

The security issue concerning the implementation of this system is that our counter is not working. In the code, the counter is initialized in a loop, which is reset after each iteration. This makes the CTR useless. We also have our keystream that is encrypted with 16 bytes of zeros. This error provides every block of 16 bytes with the same keystream since there is no counter.

By using the math formulas, we can achieve finding **V** which will be usefull to find later our plain text message. To find **V** by simply isolating it from the formula, we have an other unknown variable to find which is sigma. Sigma is going to be our key stream.

We can find sigma by substracting our plain text block from the ciphered text block. This has to be from the same message. We can chose any block, first, second, third... etc... since they all have the same keystream.

$$
\sigma = \left( (c1\_blocks[0]) - (m1\_blocks[0]) \right) \mod p
$$

The second step is to isolate **V** like so and plug in the sigma we have found previously.

$$
\text{sumM1} = \left( \sum_{i=0}^{\text{len}(m1\_blocks)-1} \text{{bytesToInt}}(m1\_blocks[i]) \right) \mod p
$$

$$
v = \left( \left((\text{tag1}) - \sigma\right) \times \text{{mod\_inverse}}(\text{{sumM1}}, p) \right) \mod p
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
\sigma = \left( (c1\_blocks[0]) - (m1\_blocks[0]) \right) \mod p
$$
By isolating our message we get this.
$$
m1\_blocks[0] = \left( \text{bytesToInt}(c1\_blocks[0]) - \sigma \right) \mod p
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