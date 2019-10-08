def detect_aes_ecb_mode(cipher: bytes) -> bool:
    """Return True if the given cipher is encrypted using AES in ECB mode"""
    if len(cipher) % 16 != 0:
        return False

    blocks_set = set()
    for i in range(0, len(cipher) // 16):
        block = cipher[16*i: 16*(i+1)]
        if block in blocks_set:
            return True
        blocks_set.add(block)
    return False


if __name__ == '__main__':
    print('Matasano\'s Crypto Set 1 - Challenge 8')
    print('Reading file 8.txt')
    with open('8.txt', 'r') as f:
        i = 1
        for line in f:
            cipher = bytes.fromhex(line.strip())
            if detect_aes_ecb_mode(cipher):
                print(f'Detected AES ECB Mode, line {i}')
                print(line.strip())
            i += 1
