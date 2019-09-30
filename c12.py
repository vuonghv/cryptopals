def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    assert len(b1) == len(b2)
    return bytes(a ^ b for a, b in zip(b1, b2))


if __name__ == '__main__':
    b1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    b2 = bytes.fromhex('686974207468652062756c6c277320657965')
    result = xor_bytes(b1, b2)
    assert result.hex() == '746865206b696420646f6e277420706c6179'
