from aes.subbytes import SubWords
from aes.rotword import RotWord

def KeyExpansion(key: bytes) -> bytes:
    """AES密钥扩展算法"""
    Rcon = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)  # 轮常数
    Nk = len(key) // 4  # 密钥长度（以字为单位）
    Nr = Nk + 6         # 轮数
    Nb = 4              # 块大小（以字为单位）
    
    # 初始化扩展密钥数组
    w = [0] * (Nb * (Nr + 1))
    
    # 将原始密钥复制到扩展密钥的前Nk个字中
    for i in range(Nk):
        w[i] = key[4*i:4*(i+1)]
    
    # 生成剩余的扩展密钥
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = RotWord(temp)   # 对temp应用RotWord变换
            temp = SubWords(temp)  # 对temp应用SubBytes变换
            temp[0] ^= Rcon[i // Nk]  # 与轮常数异或
        else:
            w[i] = [x ^ y for x, y in zip(w[i - Nk], temp)]  # 与前Nk个字异或
        
        w[i] = [w[i - Nk][j] ^ temp[j] for j in range(4)]
    
    return w

def format_words_hex(words, words_per_line=4):
    lines = []
    for i in range(0, len(words), words_per_line):
        chunk = words[i:i + words_per_line]
        line = "  ".join(" ".join(f"{b:02x}" for b in word) for word in chunk)
        lines.append(line)
    return "\n".join(lines)

# expanded = KeyExpansion([0x24, 0x75, 0xa2, 0xb3, 0x34, 0x75, 0x56, 0x88, 0x31, 0xe2, 0x12, 0x00, 0x13, 0xaa, 0x54, 0x87])
# print(format_words_hex(expanded))