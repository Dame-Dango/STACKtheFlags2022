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

def ceildiv(a, b):
    return -(-a // b)


def floordiv(a, b):
    return (a // b)

def pad_message(prefix, nbytes, m):
    prefix_len = len(prefix)
    prefix_num = int(prefix,2)
    return (int.from_bytes(m, "big") + (prefix_num << (nbytes * 8 - prefix_len))).to_bytes(nbytes,"big")

# "borrowed" from https://github.com/tl2cents/Generalized-Bleichenbacher-Attack
oracle_ctr = 0
verbose = False
def rsa_prefix_padding_oracle_attack(n, e, ct, padding_prefix, oracle):
    print('Generalized Bleichenbacher RSA Padding Oracle Attack')
    print('  for more info see 1998 paper.')
    print()

    # byte length of n
    k = int(ceildiv(math.log(n, 2), 8))
    c = ct

    # lift oracle defition to take integers
    def oracle_int(x):
        global oracle_ctr
        oracle_ctr = oracle_ctr + 1
        if oracle_ctr % 100000 == 0:
            print("[{}K tries] ".format(oracle_ctr // 1000), end='', flush=True)
        return oracle(x)
    
    prefix_nbits = len(padding_prefix)
    prefix_num = int(padding_prefix, 2)
    nbits = n.bit_length()
    B = pow(2, nbits - prefix_nbits)

    # precompute constants
    _lB = prefix_num * B
    _uB = (prefix_num + 1) * B
    padding_pos = nbits - prefix_nbits
    if verbose:
        print("[+] Testing the strict bounds, valid bounds should output : ttff")
        print((_lB >> padding_pos) == prefix_num)
        print(((_uB - 1) >> padding_pos) == prefix_num)
        print((_lB-1 >> padding_pos) == prefix_num)
        print(((_uB) >> padding_pos) == prefix_num)

    def multiply(x, y): return (x * pow(y, e, n)) % n

    # should be identity as c is valid cipher text
    c0 = multiply(c, 1)
    assert c0 == c
    i = 1
    M = [(_lB, _uB - 1)]
    s = 1

    # const_s : to enlarge the plaintext if the plaintext is too short
    const_s = None
    # ensure everything is working as expected
    if oracle_int(c0):
        # plaintext is padded correctly
        print('Oracle ok, implicit step 1 passed')
    else:
        # plaintext is not padded and might be too short
        const_s = 2**(nbits - prefix_nbits)
        c0 = multiply(c0, const_s)
        s = 1
        while not oracle_int(multiply(c0, s)):
            s += 1
        c0 = multiply(c0, s)
        assert oracle_int(c0)
        const_s *= s
        print(f"Ciphertext of unpadded message: case 1 done {s} times")

    while True:
        if i == 1:
            if verbose: print('start case 2.a: ', end='', flush=True)
            ss = ceildiv(n, _uB)
            while not oracle_int(multiply(c0, ss)):
                ss = ss + 1
            if verbose: print('done. found s1 in {} iterations: {}'.format(
                ss - ceildiv(n, _uB), ss))
        else:
            assert i > 1
            if len(M) > 1:
                if verbose: print('start case 2.b: ', end='', flush=True)
                ss = s + 1
                while not oracle_int(multiply(c0, ss)):
                    ss = ss + 1
                if verbose : print('done. found s{} in {} iterations: {}'.format(
                    i, ss-s, ss))
            else:
                if verbose: print('start case 2.c: ', end='', flush=True)
                assert len(M) == 1
                a, b = M[0]
                r = ceildiv(2 * (b * s - _lB), n)
                ctr = 0
                while True:
                    # note: the floor function below needed +1 added
                    # to it, this is not clear from the paper (see
                    # equation 2 in paper where \lt is used instead of
                    # \lte).
                    for ss in range(
                            ceildiv(_lB + r * n, b),
                            floordiv(_uB + r * n, a) + 1):
                        ctr = ctr + 1
                        if oracle_int(multiply(c0, ss)):
                            break
                    else:
                        r = r + 1
                        continue
                    break
                if verbose: print('done. found s{} in {} iterations: {}'.format(i, ctr, ss))
        # step 3, narrowing solutions
        MM = []
        for a, b in M:
            for r in range(ceildiv(a * ss - _uB + 1, n),
                           floordiv(b * ss - _lB, n) + 1):
                m = (
                    max(a, ceildiv(_lB + r * n, ss)),
                    min(b, floordiv(_uB - 1 + r * n, ss))
                )
                if m not in MM:
                    MM.append(m)
                    if verbose: print('found interval [{},{}]'.format(m[0], m[1]))
        # step 4, compute solutions
        M = MM
        s = ss
        i = i + 1
        if len(M) == 1 and M[0][0] == M[0][1]:
            print()
            print('Completed!')
            print('used the oracle {} times'.format(oracle_ctr))
            # note, no need to find multiplicative inverse of s0 in n
            # as s0 = 1, so M[0][0] is directly the message.
            if const_s != None:
                message = (M[0][0]*inverse(const_s, n) % n)
            else:
                message = M[0][0]
            m_len = (message.bit_length()-1)//8 + 1
            print("[+] decrypted message : ", message.to_bytes(m_len, 'big'))
            print('raw decryption in hex format: {}'.format(
                hex(message)))
            return


rsa_prefix_padding_oracle_attack(n, e, c, PADDING, oracle)