#%%
from Crypto.Util.number import bytes_to_long, long_to_bytes
class MAGMA:

    Pi = [[12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
          [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
          [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
          [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
          [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
          [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
          [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
          [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]]

    def __init__(self, key):
        self.key = self.key_gen(key)

    def permutation(self, num, i):
        return self.Pi[i][num]

    def rot(self, num):
        return (num << 11 | num >> 21) & 0xffffffff

    def F(self, R, k):
        R = R + k & 0xffffffff
        result = 0
        for i in range(8):
            bits = R >> 4 *(7 - i) & 0xf
            result = result << 4  |  self.Pi[7-i][bits]
        return self.rot(result)


    def key_gen(self, k):
        key = [k >> 32* (7 - i) & 0xffffffff for i in range(8)]
        return key * 3 + key[::-1]


    def encrypt(self, block):
        block = int.from_bytes(block, 'big')
        L, R = block >> 32, block & 0xffffffff
        for i in range(31):

            L, R =  R, self.F(R, self.key[i]) ^ L

        L = self.F(R, self.key[31]) ^ L
        return (L << 32 | R).to_bytes(8, 'big')

    def decrypt(self, block):
        block = int.from_bytes(block, 'big')
        L, R = block >> 32, block & 0xffffffff
        key = self.key[::-1]
        for i in range(31):

            L, R =  R, self.F(R, key[i]) ^ L

        L = self.F(R, key[31]) ^ L
        return (L << 32 | R).to_bytes(8, 'big')

# text = 0xfedcba9876543210
# text = long_to_bytes(text)
#
# c = long_to_bytes(0x4ee901e5c2d8ca3d)
# # print(hex(28da3b14))
# # print(text.bit_length())
# key = 0xffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
# magma = MAGMA(key)
# ct = magma.encrypt(text)
# # for i in key_gen(key):
# #     print(hex(i))
# # print(permutation(0xf, 0)) #fdb97531
# print(ct.hex()) #0x4ee901e5c2d8ca3d
# print(magma.decrypt(ct).hex())
#%%
