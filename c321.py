"""Matasano Cryptopals Challenge Set 3/21

Implement the MT19937 Mersenne Twister RNG
"""
# Coefficients for MT19937
W = 32
N = 624
M = 397
R = 31
F = 1812433253
A = 0x9908B0DF
B = 0x9D2C5680
C = 0xEFC60000
D = 0xFFFFFFFF
U = 11
S = 7
T = 15
L = 18

LOWER_MASK = 0x7FFFFFFF  # Binary number of R 1's
UPPER_MASK = 0x80000000  # Lowest W bits of (NOT LOWER_MASK)

DEFAULT_SEED = 5489

MT = [0] * N    # State of the generator
index = N + 1

def _int32(x: int) -> int:
    """Return lowest 32 bits of x"""
    return 0xFFFFFFFF & x

def seed_mt(seed: int):
    """Initialize the generator from a seed"""
    global MT
    global index

    index = N
    MT[0] = seed
    for i in range(1, N):
        MT[i] = _int32(F * (MT[i-1] ^ (MT[i-1] >> (W-2))) + i)

def extract_number():
    """Extract a tempered value based on MT[index]"""
    global MT
    global index

    if index >= N:
        if index > N:
            # Generator was never seeded, seed with constant like reference C
            seed_mt(DEFAULT_SEED)
        twist()

    y = MT[index]
    y ^= ((y >> U) & D)
    y ^= ((y << S) & B)
    y ^= ((y << T) & C)
    y ^= (y >> L)

    index += 1
    return _int32(y)

def twist():
    """Generate the next n values from the series x_i"""
    global MT
    global index

    for i in range(0, N):
        x = (MT[i] & UPPER_MASK) + (MT[(i+1) % N] & LOWER_MASK)
        xA = x >> 1
        # Lowest bit of x is 1
        if (x % 2) != 0:
            xA ^= A
        MT[i] = MT[(i+M) % N] ^ xA
    index = 0

def rand_int32():
    """Generate 32-bit integer"""
    return extract_number()

def rand_real():
    """Generate uniform real in [0, 1) (31-bit resolution)"""
    # Devided by 2^32
    return rand_int32() * (1.0/4294967296.0);

def _test_mt19937():
    print('Test with seed = 0')
    seed_mt(0)
    assert rand_int32() == 2357136044
    assert rand_int32() == 2546248239
    assert rand_int32() == 3071714933
    assert rand_int32() == 3626093760
    assert rand_int32() == 2588848963
    assert rand_int32() == 3684848379
    assert rand_int32() == 2340255427
    assert rand_int32() == 3638918503

    print('Test with seed = 1')
    seed_mt(1)
    assert rand_int32() == 1791095845
    assert rand_int32() == 4282876139
    assert rand_int32() == 3093770124
    assert rand_int32() == 4005303368
    assert rand_int32() == 491263
    assert rand_int32() == 550290313
    assert rand_int32() == 1298508491
    assert rand_int32() == 4290846341

    print('Test with seed = 19937')
    seed_mt(19937)
    assert rand_int32() == 1450791966
    assert rand_int32() == 204743920
    assert rand_int32() == 3492290356
    assert rand_int32() == 1071801876
    assert rand_int32() == 1454088227
    assert rand_int32() == 3623564737
    assert rand_int32() == 403508749
    assert rand_int32() == 1137468089

if __name__ == '__main__':
    print('Matasano\'s Crypto Set 3 Challenge 21')
    print('Implement MT19937 RNG')

    _test_mt19937()
