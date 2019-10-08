def padding_pkcs7(data: bytes, block_size: int) -> bytes:
    """Implement PKCS#7 Padding

    Return new bytes list whose lenght is multiple of block_size
    """
    assert 0 < block_size < 256, block_size
    remain = len(data) % block_size
    pad_byte = block_size - remain
    return data + bytes([pad_byte] * pad_byte)


def remove_padding_pkcs7(data: bytes) -> bytes:
    pad_byte = data[len(data) - 1]
    return data[:len(data) - pad_byte]


if __name__ == '__main__':
    data = b'YELLOW SUBMARINE'
    assert padding_pkcs7(data, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'

    # Test PKCS#7 Padding
    data = bytes.fromhex('001122334455')
    padding = padding_pkcs7(data, block_size=8)
    assert padding.hex() == '0011223344550202', padding.hex()

    data = bytes.fromhex('0011223344556677')
    padding = padding_pkcs7(data, block_size=8)
    assert padding.hex() == '00112233445566770808080808080808', padding.hex()

    # Test Remove PKCS#7 Padding
    data = bytes.fromhex('0011223344556601')
    unpad = remove_padding_pkcs7(data)
    assert unpad.hex() == '00112233445566', unpad.hex()

    data = bytes.fromhex('00112233445566770808080808080808')
    unpad = remove_padding_pkcs7(data)
    assert unpad.hex() == '0011223344556677', unpad.hex()
