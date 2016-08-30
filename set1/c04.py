import math
import freq_analys as f

if __name__ == '__main__':
    filename = '4.txt'
    min_score = math.inf
    key = None
    msg = None
    with open(filename, 'r') as data:
        for line in data:
            cipher = bytes.fromhex(line.strip())
            score, k, s = f.break_single_byte_xor(cipher, f.score_func)
            if score < min_score:
                min_score = score
                key = k
                msg = s
    
    print("Solution for Matasano's crypto challenge 04\n")
    print("key          : {}".format(hex(key)))
    print("decrypted msg: {}".format(msg))

    assert msg == 'Now that the party is jumping\n'
    assert key == 0x35
