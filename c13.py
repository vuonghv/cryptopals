import string
import math
import re

# English frequency from http://data-compression.com/english.shtml
ENGLISH_FREQ = {
    'A': 0.0651738,
    'B': 0.0124248,
    'C': 0.0217339,
    'D': 0.0349835,
    'E': 0.1041442,
    'F': 0.0197881,
    'G': 0.0158610,
    'H': 0.0492888,
    'I': 0.0558094,
    'J': 0.0009033,
    'K': 0.0050529,
    'L': 0.0331490,
    'M': 0.0202124,
    'N': 0.0564513,
    'O': 0.0596302,
    'P': 0.0137645,
    'Q': 0.0008606,
    'R': 0.0497563,
    'S': 0.0515760,
    'T': 0.0729357,
    'U': 0.0225134,
    'V': 0.0082903,
    'W': 0.0171272,
    'X': 0.0013692,
    'Y': 0.0145984,
    'Z': 0.0007836,
    ' ': 0.1918182,
    '*': 0.0000010  # present all punctuations as `*`
}

STAT_CHARS = string.ascii_uppercase + ' ' + '*'
ACCEPTABLE_CHARS = string.printable


def compute_score(s: str) -> float:
    """How likely a text s against English text, using Chi-squared statistic

    If score_func(s1) < score_func(s2), s1 is more likely English than s2.
    """
    if not all(c in ACCEPTABLE_CHARS for c in s):
        return math.inf

    # Treat \n \t \r like space
    s = re.sub(r'[{}]'.format(string.whitespace), ' ', s)

    # Replace all punctions with `*`, need re.escape to handle \\ character
    s = re.sub(r'[{}]'.format(re.escape(string.punctuation)), '*', s)

    # Compute Chi-squared statistic
    C = {c: 0 for c in STAT_CHARS}
    for i in s.upper():
        if i in STAT_CHARS:
            C[i] += 1
    N = sum(C.values())
    E = {i: v * N for i, v in ENGLISH_FREQ.items()}
    chi_stat = sum((C[i] - E[i])**2 / E[i] for i in C)

    return chi_stat


def break_single_byte_xor(cipher: bytes):
    """Decrypt single byte XOR and return the tuple (msg, Chi-score)"""
    min_score = math.inf
    msg = None
    for k in range(256):
        s = ''.join(chr(k ^ b) for b in cipher)
        score = compute_score(s)
        if score < min_score:
            min_score = score
            msg = s
    return msg, min_score


if __name__ == '__main__':
    cipher = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    msg, score = break_single_byte_xor(cipher)
    print('Matasano\'s Crypto Challenge 3')
    print(f'Answer: {msg}')
