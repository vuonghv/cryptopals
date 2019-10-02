import base64
import math
import c12
import c13


def compute_hamming_distance(b1: bytes, b2: bytes) -> int:
    """Return the number of differing bits"""
    assert len(b1) == len(b2)
    dist = 0
    for i, j in zip(b1, b2):
        x = i ^ j
        dist += format(x, 'b').count('1')
    return dist


def break_repeating_key_xor(cipher: bytes) -> tuple:
    # Guess the key size in bytes
    ham_avg = []
    max_key_size = 40
    for ks in range(2, max_key_size + 1):
        # Try with 4 KEYSIZE blocks give us better avg Hamming distance then 2 KEYSIZE blocks
        dist = compute_hamming_distance(cipher[:2*ks], cipher[2*ks:4 * ks])
        ham_avg.append({'ks': ks, 'ham': dist / (2*ks)})
    ham_avg.sort(key=lambda h1: h1['ham'])

    # Try 3 keysize with smallest avg Hamming distance
    max_try = 4
    plain_bytes = None
    key_bytes = None
    min_score = math.inf
    for d in ham_avg[:max_try]:
        print(f'Try key size: {d["ks"]}, Avg Hamming Distance: {d["ham"]}')
        keysize = d['ks']
        num_repeat = len(cipher) // keysize
        num_remain = len(cipher) % keysize
        # Split cipher into list of separated single-byte XOR
        single_byte_xor = []
        for i in range(0, keysize):
            cipher_i = [cipher[i + j * keysize] for j in range(0, num_repeat)]

            # Check out of index
            if num_remain and i < num_remain:
                cipher_i.append(cipher[i + num_repeat * keysize])
            single_byte_xor.append(bytes(cipher_i))
            # print(len(cipher_i), single_byte_xor[i].hex())

        single_xor_msg = []
        for i in range(0, keysize):
            decrypt_msg, score = c13.break_single_byte_xor(single_byte_xor[i])
            if decrypt_msg:
                single_xor_msg.append(decrypt_msg)

        if len(single_xor_msg) == keysize:
            # Merge keysize strings into one string
            print('Found a message')
            msg = ''
            for m in zip(*single_xor_msg):
                msg += ''.join(m)

            # Handle the remain characters
            remain = ''.join(m[len(m) - 1] for m in single_xor_msg if len(m) > num_repeat)
            msg += remain
            guess_key = c12.xor_bytes(cipher[:keysize], msg[:keysize].encode())
            if c13.compute_score(msg) < min_score:
                print('Update the new message as best guess message')
                plain_bytes = msg.encode()
                key_bytes = guess_key

    return plain_bytes, key_bytes


if __name__ == '__main__':
    s1 = 'this is a test'
    s2 = 'wokka wokka!!!'
    result = compute_hamming_distance(s1.encode(), s2.encode())
    assert result == 37
    test = compute_hamming_distance(b'B', b'A')
    assert test == 2

    with open('6.txt', 'r') as f:
        data = f.read().replace('\n', '')
        cipher = base64.b64decode(data)
        plain, key = break_repeating_key_xor(cipher)
        print(f'Decrypted Message:\n{plain.decode()}')
        print(f'KEY: "{key.decode()}"')
