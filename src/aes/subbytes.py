# Correct AES SubBytes Implementation


def gf_mult(a, b):
    """GF(2^8)乘法，模多项式 0x11B (x^8 + x^4 + x^3 + x + 1)"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B  # 模 0x11B
        b >>= 1
    return p & 0xFF

def gf_inv(x):
    """计算GF(2^8)中的乘法逆元，使用费马小定理: a^(2^8-2) = a^(-1) in GF(2^8)"""
    if x == 0:
        return 0
    
    # 在GF(2^8)中，a^254 = a^(-1)
    result = x
    for _ in range(6):
        result = gf_mult(result, result)  # 平方
        result = gf_mult(result, x)        # 乘以x
    result = gf_mult(result, result)       # 最后一次平方
    
    return result

def SubBytes(input: int):
    """AES SubBytes变换"""
    # 步骤1: 计算GF(2^8)乘法逆元
    inv = gf_inv(input)
    
    # 步骤2: 应用仿射变换
    c = 0b01100011  # 0x63
    b = 0
    for i in range(8):
        bit = ((inv >> i) & 1) ^ \
              ((inv >> ((i + 4) % 8)) & 1) ^ \
              ((inv >> ((i + 5) % 8)) & 1) ^ \
              ((inv >> ((i + 6) % 8)) & 1) ^ \
              ((inv >> ((i + 7) % 8)) & 1) ^ \
              ((c >> i) & 1)
        b |= bit << i
    
    return b


INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SubBytes(i)] = i


def InvSubBytes(input: int):
    """AES InvSubBytes变换"""
    return INV_SBOX[input]

def SubWords(state):
    """对AES状态矩阵中的每个字节应用SubBytes变换"""
    return [SubBytes(byte) for byte in state]
    

if __name__ == "__main__":
    print(SubWords([0x00, 0x01, 0x02, 0x19, 0x2c, 0x53]))  # 应该输出 [0x63, 0x7c, 0x77, 0xd4, 0x2c, 0xed]