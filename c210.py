from c11 import base64_decode
from c17 import xor, aes_encrypt, aes_decrypt
from c209 import padding_pkcs7, remove_padding_pkcs7

AES_BLOCK_SIZE = 16


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(iv) == AES_BLOCK_SIZE

    data = padding_pkcs7(data, block_size=AES_BLOCK_SIZE)
    out = b''
    prev_cipher = iv
    for i in range(0, len(data) // AES_BLOCK_SIZE):
        block = data[AES_BLOCK_SIZE*i: AES_BLOCK_SIZE*(i+1)]
        cipher = aes_encrypt(xor(block, prev_cipher), key=key)
        out += cipher
        prev_cipher = cipher
    return out


def aes_cbc_decrypt(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(iv) == AES_BLOCK_SIZE

    out = b''
    prev_cipher = iv
    # NOTE: CBC mode can be decrypted parallel
    for i in range(0, len(cipher) // AES_BLOCK_SIZE):
        block = cipher[AES_BLOCK_SIZE*i: AES_BLOCK_SIZE*(i+1)]
        decrypt_data = aes_decrypt(block, key=key)
        plain = xor(decrypt_data, prev_cipher)
        out += plain
        prev_cipher = block
    out = remove_padding_pkcs7(out)
    return out


def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    data = padding_pkcs7(data, block_size=AES_BLOCK_SIZE)
    out = b''
    for i in range(0, len(data) // AES_BLOCK_SIZE):
        block = data[AES_BLOCK_SIZE*i: AES_BLOCK_SIZE*(i+1)]
        cipher = aes_encrypt(block, key)
        out += cipher
    return out


def aes_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    assert len(cipher) % AES_BLOCK_SIZE == 0, len(cipher)
    out = b''
    for i in range(0, len(cipher) // AES_BLOCK_SIZE):
        block = cipher[AES_BLOCK_SIZE*i: AES_BLOCK_SIZE*(i+1)]
        plain = aes_decrypt(block, key)
        out += plain
    out = remove_padding_pkcs7(out)
    return out


if __name__ == '__main__':
    data = b'ATTACK AT DAWN'
    key = b'YELLOW SUBMARINE'
    iv = b'COULD YOU GET IV'

    cipher = aes_cbc_encrypt(data, key, iv)
    decrypt = aes_cbc_decrypt(cipher, key, iv)
    assert len(cipher) == 16, len(cipher)
    assert decrypt == data

    cipher = aes_ecb_encrypt(data, key)
    decrypt = aes_ecb_decrypt(cipher, key)
    assert len(cipher) == 16, len(cipher)
    assert decrypt == data

    print('Matasano\'s Crypto Set 2 Challenge 10')
    print('Reading file 10.txt')
    with open('10.txt', 'r') as f:
        content = f.read().replace('\n', '')
        cipher = base64_decode(content)
        key = b'YELLOW SUBMARINE'
        iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c'
        decrypt_msg = aes_cbc_decrypt(cipher, key=key, iv=iv)
        print('Descrypt message with AES CBC Mode:')
        print(decrypt_msg.decode())
