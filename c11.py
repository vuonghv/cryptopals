C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
D = {k: i for i, k in enumerate(C)}


def base64_encode(b: bytes) -> str:
    s = ''
    for k in range(0, len(b) // 3):
        i = 3 * k
        c1 = b[i] >> 2  # 6 firt bits of byte 1
        c2 = ((b[i] & 0x03) << 4) | (b[i + 1] >> 4)  # 2 low bits of byte 1 + 4 high bits of byte 2
        c3 = ((b[i + 1] & 0x0F) << 2) | (b[i + 2] >> 6)  # 4 low bits of byte 2 + 2 high bits of byte 3
        c4 = b[i + 2] & 0x3F    # 6 low bits of byte 3
        s += C[c1] + C[c2] + C[c3] + C[c4]

    remain = len(b) % 3
    if remain == 1:
        i = len(b) - 1
        c1 = b[i] >> 2
        c2 = (b[i] & 0x03) << 4
        s += C[c1] + C[c2] + '=='
    elif remain == 2:
        i = len(b) - 2
        c1 = b[i] >> 2
        c2 = ((b[i] & 0x03) << 4) | (b[i + 1] >> 4)
        c3 = (b[i + 1] & 0x0F) << 2
        s += C[c1] + C[c2] + C[c3] + '='
    return s


def base64_decode(s: str) -> bytes:
    if len(s) % 4 != 0:
        raise ValueError(f'Invalid length of input string ({len(s)}), must be multiple of 4')

    if not s.endswith('='):
        num_blocks = len(s) // 4
    else:
        num_blocks = (len(s) // 4) - 1

    out = b''
    for k in range(0, num_blocks):
        i = 4 * k
        c1 = D[s[i]]
        c2 = D[s[i + 1]]
        c3 = D[s[i + 2]]
        c4 = D[s[i + 3]]

        b1 = c1 << 2 | c2 >> 4
        b2 = ((c2 & 0x0F) << 4) | c3 >> 2   # 0x0F make sure b2 in 0-255 when left-shift 4
        b3 = ((c3 & 0x03) << 6) | c4        # 0x03 make sure b3 in 0-255 when left-shift 6

        out += bytes([b1, b2, b3])

    if s.endswith('=='):
        i = len(s) - 4
        c1 = D[s[i]]
        c2 = D[s[i + 1]]

        b1 = c1 << 2 | c2 >> 4
        out += bytes([b1])
    elif s.endswith('='):
        i = len(s) - 4
        c1 = D[s[i]]
        c2 = D[s[i + 1]]
        c3 = D[s[i + 2]]

        b1 = c1 << 2 | c2 >> 4
        b2 = ((c2 & 0x0F) << 4) | c3 >> 2
        out += bytes([b1, b2])

    return out


if __name__ == '__main__':
    assert base64_encode(b'pleasure.') == 'cGxlYXN1cmUu'
    assert base64_encode(b'leasure.') == 'bGVhc3VyZS4='
    assert base64_encode(b'easure.') == 'ZWFzdXJlLg=='

    assert base64_decode('YW55IGNhcm5hbCBwbGVhc3Vy') == b'any carnal pleasur'
    assert base64_decode('YW55IGNhcm5hbCBwbGVhc3U=') == b'any carnal pleasu'
    assert base64_decode('YW55IGNhcm5hbCBwbGVhcw==') == b'any carnal pleas'
