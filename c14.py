import math
import c13

with open('4.txt', 'r') as f:
    msg = None
    min_score = math.inf
    for line in f:
        cipher = bytes.fromhex(line.strip())
        s, score = c13.break_single_byte_xor(cipher)
        if score < min_score:
            min_score = score
            msg = s
    print("Matasano's crypto challenge 4")
    print(f'Answer: {msg}')
