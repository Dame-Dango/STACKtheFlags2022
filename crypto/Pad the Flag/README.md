---
layout: default
title: Pad the Flag
permalink: /:path/
parent: Cryptography
nav_order: 2
---
# Pad the Flag

> Points: 600 [1000]

## Description

> Pad the Flag

## Solution
Judging by the question name and the description, we can assume that the vulnerability in the code is related to some cryptography padding attack.

After opening the provided `source.py`, we can see that the application uses RSA with a specific padding prefix and contains the encrypted flag. It also loads the private and public key from their filesystem.
```python
ENCRYPTED_FLAG = "AAC249B3678C794D115E35E895966E69EE110F9483733602FE27075DB677EA616A5FF69FA22B7E303A4EC7D4FC39E9E62DFF1BDC7A386480F7AD1248D66061D14179B0C5455C48B329D338A9637818794532813940614F367466B49CBECB0A19E74E056170E7049F5F627ABEFB0915CDBDB9E1A5AC5AFFD2F0BE5826A0A9D0C2336CCADDC119CC64B97AF203DCF0E27D3F544A5944485BB9EE935B432BEB39B18410A78B2BC0F5585D6058B2DD3516E6B2F6375B885E6339FED7E7DCD89476D221C7C5A0EB14351373882768894FC154FAB68C45B16047AB85801198CC8050EAD6ABFC30E125A34951DDE958B1054CAE9240A52AF77A59445C20182C1FD5B601"
PADDING = b"\x00\x04"

with open("private_key.pem", "rb") as f:
    PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(f.read())

with open("public_key.pem", "rb") as f:
    RSA_PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())
```

From the `main()` function, we can see that the application will prompt the user to choose an option.
- Option `1` would print the `N` and `e` of the RSA cipher used.
- Option `2` would print the encrypted flag in hex, which is the exact same as the `ENCRYPTED_FLAG` above.
- Option `3` allows us to enter a ciphertext and decrypt it using the RSA cipher. If the ciphertext can be decrypted, it will check whether the content is padded properly, and if it is, it will print if the decrypted content matches the flag.

```python
def main():
    rsa = RSA()

    while True:
        option = int(input("option: "))

        if option == 1:
            print(f'n: {RSA_PUBLIC_KEY.n}')
            print(f'e: {RSA_PUBLIC_KEY.e}')
        elif option == 2:
            print(f'Encrypted Flag: {ENCRYPTED_FLAG}')
        elif option == 3:
            encrypted = input("Enter Encrypted Flag: ")

            plaintext = rsa.decrypt(encrypted)

            if plaintext is None:
                print("Decryption Failed!")
                continue

            if not rsa.valid(plaintext):
                print("Invalid Padding!")
                continue

            plaintext = rsa.unpad(plaintext)

            if plaintext == FLAG:
                print("The flag is correct!")
            else:
                print("The flag is incorrect!")
        else:
            print("Goodbye")
            exit(1)
```

We first connect to the server to get the `N` and `e` of the RSA cipher.
```bash
kelvin@Kelvin-Desktop:/mnt/c/Users/kelvi/Downloads/stf22/crypto_padtheflag/crypto_padtheflag$ nc xxx 32119
option: 1
n: 27745498838268342270390541832410459717876029506186104405197835711890151776448053156671628267359667675031113730557765107424510849444151656396790371676445777855008849863539302384743329990999275939998343733038454223585107152570883409665827946862924689758759230343926979376299418234007499792518418292789552633399836649032240094044536084198009044814206431438837607278069180294900543129080438000781188486862675568725667427075189589807189475163889785156857630938353589579525509381815160099955761294061615683975133026307438754024582460800766260510600437895339795565140736784017970754976295616609792522708200768185786779871199
e: 65537
option: 0
Goodbye
```

Since the question is about padding, we can assume that the padding is not done properly, which allows us to perform side channel attacks to recover the plaintext. We can use the `RSA Bleichenbacher's Attack` to recover the plaintext. 

As RSA uses multiplication, it has a unique characteristic that allows it to be homomorphic. This means that if we have two ciphertexts `c1` and `c2`, and we multiply them together, the result will be the same as if we encrypt the plaintext `m1` and `m2` separately and multiply them together. This is because `c1 * c2 = (m1 * m2) mod N`.

Based on this property, we can reduce the space needed to search for the plaintext by doing a binary search on the ciphertext.

> For more details of the attack, you can refer to the following link:
https://medium.com/@c0D3M/bleichenbacher-attack-explained-bc630f88ff25

We can then use a python script by [Karim Kanso and @tl2cents](https://github.com/tl2cents/Generalized-Bleichenbacher-Attack) to perform the attack. We just have to modify their script to change the `padding`, `ciphertext`, `N`, `e`, and most importantly, the `oracle` function that will determine if the padding is valid or not. 

```python
from pwn import *
from Crypto.Util.number import inverse, bytes_to_long

n = 27745498838268342270390541832410459717876029506186104405197835711890151776448053156671628267359667675031113730557765107424510849444151656396790371676445777855008849863539302384743329990999275939998343733038454223585107152570883409665827946862924689758759230343926979376299418234007499792518418292789552633399836649032240094044536084198009044814206431438837607278069180294900543129080438000781188486862675568725667427075189589807189475163889785156857630938353589579525509381815160099955761294061615683975133026307438754024582460800766260510600437895339795565140736784017970754976295616609792522708200768185786779871199
e = 65537
c = 'AAC249B3678C794D115E35E895966E69EE110F9483733602FE27075DB677EA616A5FF69FA22B7E303A4EC7D4FC39E9E62DFF1BDC7A386480F7AD1248D66061D14179B0C5455C48B329D338A9637818794532813940614F367466B49CBECB0A19E74E056170E7049F5F627ABEFB0915CDBDB9E1A5AC5AFFD2F0BE5826A0A9D0C2336CCADDC119CC64B97AF203DCF0E27D3F544A5944485BB9EE935B432BEB39B18410A78B2BC0F5585D6058B2DD3516E6B2F6375B885E6339FED7E7DCD89476D221C7C5A0EB14351373882768894FC154FAB68C45B16047AB85801198CC8050EAD6ABFC30E125A34951DDE958B1054CAE9240A52AF77A59445C20182C1FD5B601'
c = int.from_bytes(bytes.fromhex(c), 'big')
PADDING = bin(bytes_to_long(b"\x00\x04"))[2:].zfill(16)

conn = remote('xxx', 32119)

def oracle(num) -> int:
    conn.recvuntil(b'option: ')
    conn.sendline(b'3')
    conn.recvuntil(b'Enter Encrypted Flag: ')
    payload = hex(num)[2:].zfill(512).encode()
    conn.sendline(payload)
    res = conn.recvuntil(b'\n').decode().strip()
    if res == 'The flag is correct!' or res =='The flag is incorrect!':
        return True
    if 'hexadecimal' in res:
        print(res)
        print(payload)
    return False

# "borrowed" from https://github.com/tl2cents/Generalized-Bleichenbacher-Attack
oracle_ctr = 0
verbose = False
def rsa_prefix_padding_oracle_attack(n, e, ct, padding_prefix, oracle):
    # See solve.py and the link above for the full implementation
    print('Generalized Bleichenbacher RSA Padding Oracle Attack')
    print('  for more info see 1998 paper.')
    print()
    # ...

rsa_prefix_padding_oracle_attack(n, e, c, PADDING, oracle)
```

We then run the python script `solve.py` and we are able to get the flag from the server.
```
kelvin@Kelvin-Desktop:/mnt/c/Users/kelvi/Downloads/stf22/crypto_padtheflag/crypto_padtheflag$ python3 solve.py 
[+] Opening connection to xxx on port 32119: Done
Generalized Bleichenbacher RSA Padding Oracle Attack
  for more info see 1998 paper.

Oracle ok, implicit step 1 passed

Completed!
used the oracle 10452 times
[+] decrypted message :  b'\x04IE\xde+\x97\x1fPU3\x81\n\\\xa6\x952\xf3\xe1\xadJ\xba$(\x8d\x01\t\xff v0\xe2?\xdf#\xbcH{=\xeeO\xdc\x91\xdd\xe7T\x8f\xb1\xaa\xc4:\x1d\xc6a\xa0\x02*\xf78\xa2\xefQ\x87bG\x0b\x93\xfcd\x9b\x83\xf8\x1e\x86<\xf4\x10\x08\x92`\x80\xd4\x82\x7fD\x9c6\xd75\x04\xc8p\xc0wS\xf6Rx\xa9\xbfnZ\x19s9Y\xb4\xa1!41\xfd\xeaz\xc7\x84j\xbd\xcc\xe4&\xf9f\x8b\x17\x9e\x0e\x12|F\xc1\xec\xfb\xd8%g}\xf0\xaf\xb8C]\xed\x8a\xd9\x16\x06;\xab\x85\xca\x13\xf2\xcf)"i\xf5y\xa4N\xe5\xd0\x18\xa8\xd1[c_\xd2MW\xd5\'o\xb9\xa5\xc9,K\xdb\xe6t\x96\xce\xae\xb7\r~^\xe9\xfa.\xfeA\x88\x8c\x14-\xbb\xcb\x99qX\x98\xc37l\x89\xb6\xc2\xe8\xe3\x1c\x9a\xb2\xbeu\x9d\xa7\x0c\x90\x00STF22{p@dd1ng_pr0b13m_3v3rywh3r3}'
raw decryption in hex format: 0x44945de2b971f505533810a5ca69532f3e1ad4aba24288d0109ff207630e23fdf23bc487b3dee4fdc91dde7548fb1aac43a1dc661a0022af738a2ef518762470b93fc649b83f81e863cf41008926080d4827f449c36d73504c870c07753f65278a9bf6e5a19733959b4a1213431fdea7ac7846abdcce426f9668b179e0e127c46c1ecfbd825677df0afb8435ded8ad916063bab85ca13f2cf292269f579a44ee5d018a8d15b635fd24d57d5276fb9a5c92c4bdbe67496ceaeb70d7e5ee9fa2efe41888c142dbbcb99715898c3376c89b6c2e8e31c9ab2be759da70c900053544632327b70406464316e675f7072306231336d5f337633727977683372337d
[*] Closed connection to xxx port 32119
```

## Flag
`STF22{p@dd1ng_pr0b13m_3v3rywh3r3}`