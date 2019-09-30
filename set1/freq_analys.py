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

STATISTIC_CHARS = string.ascii_uppercase + ' ' + '*'
ACCEPTABLE_CHARS = string.printable

def load_ngrams_freq(filename: str, sep: str=' ') -> dict:
    data = {}
    with open(filename, 'r') as f:
        for line in f:
            ngram, count = line.split(sep)
            data[ngram] = int(count)
    N = sum(data.values())
    freq = {k: v/N for k, v in data.items()}
    return freq

def count_letters(s: str) -> dict:
    """Return dict of number letters in string s
    """
    counts = {c: 0 for c in STATISTIC_CHARS}
    for c in s.upper():
        if c in STATISTIC_CHARS: counts[c] += 1
    return counts

def chi_squared(observed: dict, expected: dict) -> float:
    """Compute Chi-squared statistic
    """
    chi_stat = 0.0
    for k in expected:
        chi_stat += (observed[k] - expected[k])**2 / expected[k]
    return chi_stat

def score_func(s: str) -> float:
    """How likely a text s against English text, using Chi-squared statistic

    If score_func(s1) < score_func(s2), s1 is more likely English than s2.
    """
    if not all(c in ACCEPTABLE_CHARS for c in s):
        return math.inf

    # treat \n \t \r like space
    s = re.sub('[{}]'.format(string.whitespace), ' ', s)

    # replace all punctions with `*`
    s = re.sub('[{}]'.format(string.punctuation), '*', s)

    observed = count_letters(s)
    N = sum(observed.values())
    expected = {k: v*N for k,v in ENGLISH_FREQ.items()}
    score = chi_squared(observed, expected)
    return score

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

def break_single_byte_xor(cipher: bytes, score_func) -> (float, int, str):
    msg = None
    min_score = math.inf
    key = None
    for k in range(256):
        s = ''.join(chr(k^b) for b in cipher)
        score = score_func(s)
        if score < min_score:
            min_score = score
            key = k
            msg = s
    return (min_score, key, msg)
