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

The next step is to 

$$
\sigma_2 = \left( \left((\text{{tag2}}) - v \times \text{{sumC2}}\right) \times \text{{mod\_inverse}}(1 - v \times n, p) \right) \mod p
$$


$$
\text{sumC2} = \left( \sum_{i=0}^{\text{len}(c2\_blocks)-1} \text{{bytesToInt}}(c2\_blocks[i]) \right) \mod p
$$



## HMac