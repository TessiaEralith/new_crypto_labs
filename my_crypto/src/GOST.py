#%% md
# # Кузнечик
#%% md
# ## Основные преобразования
#%%



class GOST:
    def __init__(self, key):
        self.C = [self.L(bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i])) for i in range(1, 33)]
        self.key = self.key_extend(key)


    pi = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
          119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101,
          90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
          160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
          104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
          183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
          177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
          245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
          222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0,
          98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
          165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
          217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133,
          97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
          116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]

    l_const = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]


    def S(self, bytes_string: bytes) -> bytes:
        return bytes([self.pi[byte] for byte in bytes_string])

    def invS(self, bytes_string: bytes) -> bytes:
        return bytes([self.pi.index(byte) for byte in bytes_string])

    def mul_2(self, num: int) -> int:
        num <<= 1
        if num.bit_length() > 8:
            num &= 0xff
            num ^= 0xc3
        return num

    def mul(self, a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a = self.mul_2(a)
            b >>= 1
        return result

    def l(self, bytes_string: bytes) -> bytes:
        result_byte = 0
        for byte, c in zip(bytes_string, self.l_const):
            result_byte ^= self.mul(byte, c)
        return bytes([result_byte])


    def R(self, bytes_string: bytes) -> bytes:
        return self.l(bytes_string) + bytes_string[:-1]

    def invR(self, bytes_string: bytes) -> bytes:
        return bytes_string[1:] + self.l(bytes_string[1:] + bytes_string[:1])

    def L(self, bytes_string: bytes) -> bytes:
        for i in range(16):
            bytes_string = self.R(bytes_string)
        return bytes_string

    def invL(self, bytes_string: bytes) -> bytes:
        for i in range(16):
            bytes_string = self.invR(bytes_string)
        return bytes_string

    def xor(self, bytes_string: bytes, key: bytes) -> bytes:
        return bytes([a ^ b for a, b in zip(bytes_string, key)])



    #%% md
    # ## Развертка ключа
    #%%


    def key_extend(self, key: bytes) -> list[bytes]:
        k_1, k_2 = key[:16], key[16:]
        k = [k_1, k_2]
        for i in range(4):
            for j in range(8):
                k_2, k_1 = k_1, self.xor(self.L(self.S(self.xor(k_1, self.C[i*8 + j]))), k_2)
            k+= [k_1, k_2]
        return k


    # key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

    #%% md
    # ## Шифрование и расшифрование
    #%%
    def encrypt(self, bytes_string: bytes) -> bytes:
        for i in range(9):
            bytes_string = self.L(self.S(self.xor(bytes_string, self.key[i])))
        return self.xor(bytes_string, self.key[9])

    def decrypt(self, bytes_string: bytes) -> bytes:
        K = self.key[::-1]
        for i in range(9):
            bytes_string = self.invS(self.invL(self.xor(bytes_string, K[i])))
        return self.xor(bytes_string, K[9])
key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
gost = GOST(key)
text = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
ct = gost.encrypt(text)
check_text = gost.decrypt(ct)
print(check_text.hex())
#%%
