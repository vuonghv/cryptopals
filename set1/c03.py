import freq_analys as f

if __name__ == '__main__':
    data = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    cipher = bytes.fromhex(data)
    _, key, msg = f.break_single_byte_xor(cipher, f.score_func)

    print("Solution for Matasano's crypto challenge 03\n")
    print('cipher (hex) : {}'.format(data))
    print('key          : {}'.format(hex(key)))
    print('decrypted msg: {}'.format(msg))

    assert msg == "Cooking MC's like a pound of bacon"
    assert key == 0x58

