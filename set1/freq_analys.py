import string
import math
import re

ENGLISH_FREQ = {
    'A': 0.08167,
    'B': 0.01492,
    'C': 0.02782,
    'D': 0.04253,
    'E': 0.12702,
    'F': 0.02228,
    'G': 0.02015,
    'H': 0.06094,
    'I': 0.06966,
    'J': 0.00153,
    'K': 0.00772,
    'L': 0.04025,
    'M': 0.02406,
    'N': 0.06749,
    'O': 0.07507,
    'P': 0.01929,
    'Q': 0.00095,
    'R': 0.05987,
    'S': 0.06327,
    'T': 0.09056,
    'U': 0.02758,
    'V': 0.00978,
    'W': 0.02360,
    'X': 0.00150,
    'Y': 0.01974,
    'Z': 0.00074
}

def load_ngrams_freq(filename: str, sep: str=' ') -> dict:
    data = {}
    with open(filename, 'r') as f:
        for line in f.readlines():
            d = line.strip().split(sep)
            data[d[0]] = int(d[1])
    N = sum(v for v in data.values())
    freq = {k: v/N for k, v in data.items()}
    return freq

def count_letters(s: str) -> dict:
    """Return dict of number letters in string s
    """
    counts = {c: 0 for c in string.ascii_uppercase}
    for c in s.upper():
        if c in string.ascii_uppercase:
            counts[c] += 1
    return counts

def chi_squared(s: str) -> float:
    """Chi-squared statistic value of s against English distribution
    """
    if not all(c in string.printable for c in s):
        return math.inf

    C = count_letters(s)
    total = sum(C.values())
    if not total: return math.inf
    chi_stat = 0.0
    for i in string.ascii_uppercase:
        expected = ENGLISH_FREQ[i] * total
        diff = C[i] - expected
        chi_stat += (diff*diff / expected)
    return chi_stat

def index_of_coin(s: str) -> float:
    """Compute Index of Coincidence (IC)"""
    if not all(c in string.printable for c in s):
        return math.inf
    s = re.sub(r'[^A-Z]', '', s.upper())
    N = len(s)
    if not N: return math.inf
    IC = 0
    for c in string.ascii_uppercase:
        count = s.count(c)
        IC += count * (count - 1)
    IC /= N * (N - 1)
    return IC

def break_single_byte_xor(cipher: bytes) -> (str, float):
    msg = None
    score = math.inf
    for key in range(256):
        s = ''.join(chr(key^b) for b in cipher)
        chi = chi_squared(s)
        if chi < score:
            score = chi
            msg = s
    return (msg, score)

