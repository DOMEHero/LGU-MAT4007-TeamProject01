from aes.subbytes import SubBytes, InvSubBytes, gf_mult

class Block:
    def __init__(self, data: bytes):
        if len(data) != 16:
            raise ValueError("Block must be 16 bytes long")
        self.data = [[data[j + i * 4] for i in range(4)] for j in range(4)]  # 4x4字节矩阵
        # self.rep = [[hex(data[j + i * 4]) for i in range(4)] for j in range(4)] 

    def __bytes__(self):
        return bytes([self.data[j][i] for i in range(4) for j in range(4)])

    def __repr__(self):
        return f"Block({self.data})"
    
    def __xor__(self, other):
        if not isinstance(other, Block):
            raise TypeError("XOR operation requires another Block")
        result_data = [self.data[j][i] ^ other.data[j][i] for i in range(4) for j in range(4)]
        return Block(bytes(result_data))

    def ByteSub(self):
        """对Block中的每个字节应用SubBytes变换"""
        self.data = [[SubBytes(byte) for byte in row] for row in self.data]

    def InvByteSub(self):
        """对Block中的每个字节应用InvSubBytes变换"""
        self.data = [[InvSubBytes(byte) for byte in row] for row in self.data]

    def ShiftRows(self):
        """对Block中的行进行循环左移"""
        self.data[1] = self.data[1][1:] + self.data[1][:1]  # 第二行左移1
        self.data[2] = self.data[2][2:] + self.data[2][:2]  # 第三行左移2
        self.data[3] = self.data[3][3:] + self.data[3][:3]  # 第四行左移3

    def InvShiftRows(self):
        """对Block中的行进行循环右移"""
        self.data[1] = self.data[1][-1:] + self.data[1][:-1]  # 第二行右移1
        self.data[2] = self.data[2][-2:] + self.data[2][:-2]  # 第三行右移2
        self.data[3] = self.data[3][-3:] + self.data[3][:-3]  # 第四行右移3
    
    def MixColumns(self):
        """对Block中的列进行混合"""
        def mix_column(column):
            a = column
            b = [(((a[i] << 1) & 0xff) ^ (0x1b if a[i] & 0x80 else 0)) for i in range(4)] # 乘以2的结果，如果最高位是1则需要异或0x1b
            return [
                b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1],
                b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2],
                b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3],
                b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]
            ] # 乘以3的结果等于乘以2的结果加上原来的值，即b[i] ^ a[i]
        
        for i in range(4):
            column = [self.data[j][i] for j in range(4)]
            mixed_column = mix_column(column)
            for j in range(4):
                self.data[j][i] = mixed_column[j]

    def InvMixColumns(self):
        """对Block中的列进行逆混合"""
        for i in range(4):
            a0, a1, a2, a3 = [self.data[j][i] for j in range(4)]
            self.data[0][i] = gf_mult(a0, 0x0e) ^ gf_mult(a1, 0x0b) ^ gf_mult(a2, 0x0d) ^ gf_mult(a3, 0x09)
            self.data[1][i] = gf_mult(a0, 0x09) ^ gf_mult(a1, 0x0e) ^ gf_mult(a2, 0x0b) ^ gf_mult(a3, 0x0d)
            self.data[2][i] = gf_mult(a0, 0x0d) ^ gf_mult(a1, 0x09) ^ gf_mult(a2, 0x0e) ^ gf_mult(a3, 0x0b)
            self.data[3][i] = gf_mult(a0, 0x0b) ^ gf_mult(a1, 0x0d) ^ gf_mult(a2, 0x09) ^ gf_mult(a3, 0x0e)