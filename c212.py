"""Matasano Cryptopals Challenge Set 2/12

Byte-at-a-time ECB Decryption (Simple)
"""
import os
from c11 import base64_decode
from c210 import aes_ecb_encrypt

random_key = os.urandom(16)


def detect_block_size():
    """Detect Block Size of Cipher"""
    # TODO: Need to implement, tempolary using AES
    return 16


def detect_ecb_mode():
    """Return True if the current cipher is encrypted under ECB mode"""
    # TODO: Need to implement, tempolary using AES ECB mode
    return True


def encrypt_oracle(your_msg: bytes, unknown_msg: bytes) -> bytes:
    # By updating your_msg input and examine the output cipher,
    # guess the first byte of unknown_msg
    # your_msg is appended with unknown_msg
    concat_msg = your_msg + unknown_msg
    cipher = aes_ecb_encrypt(concat_msg, key=random_key)
    return cipher


def decrypt_ecb_byte_at_a_time(unknown_msg: bytes) -> int:
    block_size = detect_block_size()
    adjust_input = b'A' * (block_size - 1)
    cipher = encrypt_oracle(adjust_input, unknown_msg)
    if not detect_ecb_mode():
        raise ValueError('Not an ECB mode')

    # first_cipher_block is encryption of "AAAAAAAAAAAAAAA + unknown_msg[0]"
    first_cipher_block = cipher[:block_size]
    # Try all 256 value of unknown_msg[0]
    for b in range(0, 256):
        adjust_input = b'A' * (block_size - 1) + bytes([b])
        cipher = aes_ecb_encrypt(adjust_input, key=random_key)
        if cipher[:block_size] == first_cipher_block:
            return b
    raise ValueError('Cannot decrypt the first byte')


if __name__ == '__main__':
    # We need to guess this unknown_str without decode it
    unknown_str = (
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
        'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
        'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    )
    unknown_msg = base64_decode(unknown_str)
    decrypt_msg = b''
    for i in range(0, len(unknown_msg)):
        # Only need the first byte of the message for performance
        decrypt_byte = decrypt_ecb_byte_at_a_time(unknown_msg[i:i+1])
        print(f'Decrypt byte {i}: 0x{decrypt_byte:02x} => {chr(decrypt_byte)}')
        decrypt_msg += bytes([decrypt_byte])

    assert decrypt_msg == unknown_msg
    print('Matasano\'s Crypto Set 2 Challenge 12')
    print(f'Unknown base64 str:\n{unknown_str}\n')
    print('Descrypt string (using byte-at-a-time ECB Decryption):')
    print(decrypt_msg.decode())
