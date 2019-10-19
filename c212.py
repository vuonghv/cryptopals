"""Matasano Cryptopals Challenge Set 2/12

Byte-at-a-time ECB Decryption (Simple)
"""
import os
from c11 import base64_decode
from c210 import aes_ecb_encrypt

# Random AES key
random_key = os.urandom(16)


def detect_block_size():
    """Detect Block Size of Cipher"""
    # Feed bytes to the oracle function, starts with 1 byte "A", then "AA",
    # then "AAA", so on. Until the return cipher increases its length because
    # of padding - the length of (feed bytes + unknow_msg) is multiple of
    # block_size. The increasing cipher's length is block_size
    max_block_size = 64
    prev_cipher_len = 0
    for i in range(1, max_block_size + 1):
        cipher = encrypt_oracle(b'A' * i)
        if prev_cipher_len and prev_cipher_len < len(cipher):
            return len(cipher) - prev_cipher_len
        else:
            prev_cipher_len = len(cipher)
    raise ValueError('Cannot detect block size')


def detect_ecb_mode(block_size: int) -> bool:
    """Return True if the current cipher is encrypted under ECB mode"""
    # Feed the amount of identical bytes and check the repeated blocks
    feed_bytes = b'A' * 100
    cipher = encrypt_oracle(feed_bytes)

    blocks_set = set()
    for i in range(0, len(cipher) // block_size):
        block = cipher[block_size*i: block_size*(i+1)]
        if block in blocks_set:
            return True
        blocks_set.add(block)
    return False


def encrypt_oracle(your_msg: bytes) -> bytes:
    """Return AES-128-ECB(your_msg || unknown_msg, random-key)"""
    # Our mission is finding out this unkown_msg
    unknown_msg = base64_decode(
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
        'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
        'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    )
    concat_msg = your_msg + unknown_msg
    cipher = aes_ecb_encrypt(concat_msg, key=random_key)
    return cipher


def decrypt_ecb_byte_at_a_time() -> bytes:
    block_size = detect_block_size()
    if not detect_ecb_mode(block_size):
        raise ValueError('Not an ECB mode')

    # Without your_msg
    original_cipher = encrypt_oracle(b'')
    secret_msg = b''
    for i in range(0, len(original_cipher) // block_size):
        for j in range(0, block_size):
            # j-byte-short
            input_msg = b'A' * (block_size - 1 - j)

            # one_byte_short is encryption of "AAAAAAAAAAAAAAA || unknown_msg[0]"
            one_byte_short = encrypt_oracle(input_msg)[i*block_size:i*block_size + block_size]

            # Try all 256 value of unknown_msg[0]
            found = False
            for b in range(0, 256):
                adjust_input = input_msg + secret_msg + bytes([b])
                cipher = encrypt_oracle(adjust_input)
                if cipher[i*block_size:i*block_size + block_size] == one_byte_short:
                    print(f'Decrypt byte {i*block_size+j}: 0x{b:02x} => {chr(b)}')
                    found = True
                    secret_msg += bytes([b])
                    break
            if not found:
                # Remove the last padding byte (0x01) - PKCS#7 padding
                return secret_msg[:-1]
    return secret_msg


if __name__ == '__main__':
    # We need to guess this unknown_str without decode it
    unknown_msg = base64_decode(
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
        'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
        'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    )
    decrypt_msg = decrypt_ecb_byte_at_a_time()

    assert decrypt_msg == unknown_msg, len(decrypt_msg)
    print('Matasano\'s Crypto Set 2 Challenge 12')
    print('Descrypt string (using byte-at-a-time ECB Decryption):')
    print(decrypt_msg.decode())
