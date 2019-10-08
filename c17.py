"""Implement AES Standard

Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
"""
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

INV_SBOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

# Mapping num key to num rounds
ROUND_MAP = {4: 10, 6: 12, 8: 14}

# Pre compute Rcon[i] = X**(i-1) in GF(2**8)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(a, b))


def xtime(b: int) -> int:
    # Check if bit-7 is set
    if not b & 0x80:
        return b << 1
    x = (b << 1) & 0xFF
    return x ^ 0x1B


def gmul(a: int, b: int) -> int:
    """Multiple 2 bytes in GF(2^8) field

    Ref: Section 4.2 in NIST.FIPS.197
    """
    # Pre compute xtime(a) for all X^0 ... X^7
    xtime_a = [a]
    for i in range(1, 8):
        n = xtime(xtime_a[i - 1])
        xtime_a.append(n)

    value = 0
    for i in range(0, 8):
        if b & (1 << i):
            value ^= xtime_a[i]
    return value


def input_to_state(in_bytes: bytes) -> bytes:
    """Convert input bytes to AES state"""
    out = bytearray(16)
    for r in range(0, 4):
        for c in range(0, 4):
            out[r*4 + c] = in_bytes[r + 4*c]
    return bytes(out)


def state_to_output(state: bytes) -> bytes:
    """Convert AES state to output bytes"""
    out = bytearray(16)
    for r in range(0, 4):
        for c in range(0, 4):
            out[r + 4*c] = state[r*4 + c]
    return bytes(out)


def sub_bytes(state: bytes) -> bytes:
    assert len(state) == 16
    new_state = bytes(SBOX[i] for i in state)
    return new_state


def inv_sub_bytes(state: bytes) -> bytes:
    assert len(state) == 16
    new_state = bytes(INV_SBOX[i] for i in state)
    return new_state


def shift_rows(state: bytes) -> bytes:
    assert len(state) == 16
    row_0 = state[0:4]  # Not shifted
    row_1 = state[5:8] + state[4:5]      # Left shift 1
    row_2 = state[10:12] + state[8:10]   # Left shift 2
    row_3 = state[15:16] + state[12:15]  # Left shift 3
    return row_0 + row_1 + row_2 + row_3


def inv_shift_rows(state: bytes) -> bytes:
    assert len(state) == 16
    row_0 = state[0:4]  # Not shifted
    row_1 = state[7:8] + state[4:7]      # Left shift 1
    row_2 = state[10:12] + state[8:10]   # Left shift 2
    row_3 = state[13:16] + state[12:13]  # Left shift 3
    return row_0 + row_1 + row_2 + row_3


def mix_columns(state: bytes) -> bytes:
    assert len(state) == 16
    out = bytearray(16)
    for c in range(0, 4):
        out[c] = gmul(0x02, state[c]) ^ gmul(0x03, state[4+c]) ^ state[8+c] ^ state[12+c]
        out[4+c] = state[c] ^ gmul(0x02, state[4+c]) ^ gmul(0x03, state[8+c]) ^ state[12+c]
        out[8+c] = state[c] ^ state[4+c] ^ gmul(0x02, state[8+c]) ^ gmul(0x03, state[12+c])
        out[12+c] = gmul(0x03, state[c]) ^ state[4+c] ^ state[8+c] ^ gmul(0x02, state[12+c])
    return bytes(out)


def inv_mix_columns(state: bytes) -> bytes:
    assert len(state) == 16
    out = bytearray(16)
    for c in range(0, 4):
        out[c] = gmul(0x0e, state[c]) ^ gmul(0x0b, state[4+c]) ^ gmul(0x0d, state[8+c]) ^ gmul(0x09, state[12+c])
        out[4+c] = gmul(0x09, state[c]) ^ gmul(0x0e, state[4+c]) ^ gmul(0x0b, state[8+c]) ^ gmul(0x0d, state[12+c])
        out[8+c] = gmul(0x0d, state[c]) ^ gmul(0x09, state[4+c]) ^ gmul(0x0e, state[8+c]) ^ gmul(0x0b, state[12+c])
        out[12+c] = gmul(0x0b, state[c]) ^ gmul(0x0d, state[4+c]) ^ gmul(0x09, state[8+c]) ^ gmul(0x0e, state[12+c])
    return bytes(out)


def add_round_key(state: bytes, round_key: bytes) -> bytes:
    assert len(state) == len(round_key)
    return bytes(a ^ b for a, b in zip(state, round_key))


def sub_word(word: bytes) -> bytes:
    return bytes(SBOX[i] for i in word)


def rot_word(word: bytes) -> bytes:
    return word[1:4] + word[:1]


def expand_key(key: bytes) -> bytes:
    """AES Key Expansion"""
    assert len(key) in (16, 24, 32)
    nb = 4
    nk = len(key) // 4   # One of 4, 6, 8
    nr = ROUND_MAP[nk]

    words = bytearray(4 * nb * (nr + 1))
    for i in range(0, nk):
        k = 4 * i
        words[k:k + 4] = key[k:k + 4]

    for i in range(nk, nb * (nr + 1)):
        temp = bytes(words[4 * (i - 1): 4 * i])
        if i % nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            rcon_i = bytes([RCON[i//nk - 1], 0, 0, 0])
            temp = xor(temp, rcon_i)
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)

        words[4*i: 4*i + 4] = xor(words[4*(i-nk): 4*(i-nk) + 4], temp)

    return bytes(words)


def aes_encrypt(block: bytes, key: bytes) -> bytes:
    assert len(block) == 16
    assert len(key) in (16, 24, 32)

    nb = 4
    nk = len(key) // 4   # One of 4, 6, 8
    nr = ROUND_MAP[nk]

    words = expand_key(key)
    state = input_to_state(block)
    state = add_round_key(state, input_to_state(words[0:16]))

    for r in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, input_to_state(words[4*nb*r: 4*nb*(r+1)]))

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, input_to_state(words[4*nr*nb: 4*(nr+1)*nb]))

    cipher = state_to_output(state)
    return cipher


def aes_decrypt(block: bytes, key: bytes) -> bytes:
    assert len(block) == 16
    assert len(key) in (16, 24, 32)

    nb = 4
    nk = len(key) // 4   # One of 4, 6, 8
    nr = ROUND_MAP[nk]

    words = expand_key(key)
    state = input_to_state(block)
    state = add_round_key(state, input_to_state(words[4*nb*nr: 4*nb*nr + 16]))
    for r in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, input_to_state(words[4*nb*r: 4*nb*r+16]))
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, input_to_state(words[0:16]))

    plain = state_to_output(state)
    return plain


if __name__ == '__main__':
    assert xor(b'1234', b'4321') == b'\x05\x01\x01\x05'
    print('Test xor() success')

    assert xtime(0x57) == 0xAE
    assert xtime(0xAE) == 0x47
    assert xtime(0x47) == 0x8E
    assert xtime(0x8E) == 0x07
    print('Test xtime() success')

    assert gmul(0x57, 0x01) == 0x57
    assert gmul(0x57, 0x02) == 0xAE
    assert gmul(0x57, 0x10) == 0x07
    assert gmul(0x57, 0x13) == 0xFE
    print('Test gmul() success')

    assert rot_word(bytes.fromhex('09cf4f3c')).hex() == 'cf4f3c09'
    assert rot_word(bytes.fromhex('2a6c7605')).hex() == '6c76052a'
    assert rot_word(bytes.fromhex('7359f67f')).hex() == '59f67f73'
    print('Test rot_word() success')

    assert sub_word(bytes.fromhex('cf4f3c09')).hex() == '8a84eb01'
    assert sub_word(bytes.fromhex('6c76052a')).hex() == '50386be5'
    assert sub_word(bytes.fromhex('59f67f73')).hex() == 'cb42d28f'
    print('Test sub_word() success')

    actual = sub_bytes(bytes.fromhex('89d810e8855ace682d1843d8cb128fe4'))
    assert actual.hex() == 'a761ca9b97be8b45d8ad1a611fc97369'
    print('Test sub_bytes() success')

    actual = inv_sub_bytes(bytes.fromhex('7a9f102789d5f50b2beffd9f3dca4ea7'))
    assert actual.hex() == 'bd6e7c3df2b5779e0b61216e8b10b689'
    print('Test inv_sub_bytes() success')

    state = input_to_state(bytes.fromhex('a761ca9b97be8b45d8ad1a611fc97369'))
    actual2 = state_to_output(shift_rows(state))
    assert actual2.hex() == 'a7be1a6997ad739bd8c9ca451f618b61'
    print('Test convert input -> state -> output success')

    # Test shift rows
    state = input_to_state(bytes.fromhex('63cab7040953d051cd60e0e7ba70e18c'))
    actual = shift_rows(state)
    assert state_to_output(actual).hex() == '6353e08c0960e104cd70b751bacad0e7'
    print('Test shift_rows() success')

    state = input_to_state(bytes.fromhex('7ad5fda789ef4e272bca100b3d9ff59f'))
    actual = inv_shift_rows(state)
    assert state_to_output(actual).hex() == '7a9f102789d5f50b2beffd9f3dca4ea7'
    print('Test inv_shift_rows() success')

    # Test mix columns
    state2 = input_to_state(bytes.fromhex('a7be1a6997ad739bd8c9ca451f618b61'))
    actual3 = mix_columns(state2)
    assert state_to_output(actual3).hex() == 'ff87968431d86a51645151fa773ad009'
    print('Test mix_columns() success')

    state2 = input_to_state(bytes.fromhex('fde3bad205e5d0d73547964ef1fe37f1'))
    actual3 = inv_mix_columns(state2)
    assert state_to_output(actual3).hex() == '2d7e86a339d9393ee6570a1101904e16'
    print('Test inv_mix_columns() success')

    # Test 128-bits Key Expansion
    key128 = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    exp_key = expand_key(key128)
    assert len(exp_key) == 4 * 4 * (10 + 1)  # nr = 10
    assert exp_key[:16].hex() == '2b7e151628aed2a6abf7158809cf4f3c'
    assert exp_key[len(exp_key) - 16:].hex() == 'd014f9a8c9ee2589e13f0cc8b6630ca6'

    # Test 192-bits Key Expansion
    key192 = bytes.fromhex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b')
    exp_key = expand_key(key192)
    assert len(exp_key) == 4 * 4 * (12 + 1)
    assert exp_key[:16].hex() == '8e73b0f7da0e6452c810f32b809079e5'
    assert exp_key[len(exp_key) - 16:].hex() == 'e98ba06f448c773c8ecc720401002202'
    print('Test expand_key() success')

    # Test AES encrypt
    block = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    cipher = aes_encrypt(block, key)
    assert cipher.hex() == '3925841d02dc09fbdc118597196a0b32', cipher.hex()

    block = bytes.fromhex('00112233445566778899aabbccddeeff')
    key128 = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    cipher = aes_encrypt(block, key128)
    assert cipher.hex() == '69c4e0d86a7b0430d8cdb78070b4c55a', cipher.hex()
    print('Test AES encrypt success')

    # Test AES decrypt
    key128 = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    cipher = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    plain = aes_decrypt(cipher, key128)
    assert plain.hex() == '00112233445566778899aabbccddeeff', plain.hex()
    print('Test AES decrypt success')

    print('Matasano\'s Crypto Set 1 - Challenge 7')
    key = b'YELLOW SUBMARINE'
    plain = b''
    print('Reading file 7.txt')
    with open('7.txt', 'r') as f:
        import c11
        content = f.read().replace('\n', '')
        cipher = c11.base64_decode(content)
        for i in range(0, len(cipher) // 16):
            plain += aes_decrypt(cipher[16*i: 16*(i+1)], key)
    print(f'KEY: {key.decode()}')
    print(f'DECRYPT MESSAGE:\n{plain.decode()}')
