import c12


def repeat_key_xor(key: bytes, data: bytes) -> bytes:
    num = len(data) // len(key)
    expand_key = key * num
    expand_key += key[:len(data) % len(key)]
    return c12.xor_bytes(expand_key, data)


if __name__ == '__main__':
    key = 'ICE'.encode()
    data = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode()
    cipher = repeat_key_xor(key, data)
    assert cipher.hex() == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
