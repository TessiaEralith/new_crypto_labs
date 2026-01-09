from random import randbytes
M = [[207, 152, 116, 191, 147, 142, 242, 243, 10, 191, 246, 169, 234, 142, 77, 110],
     [110, 32, 198, 218, 144, 72, 137, 156, 193, 100, 184, 45, 134, 68, 208, 162],
     [162, 200, 135, 112, 104, 67, 28, 43, 161, 99, 48, 107, 159, 48, 227, 118],
     [118, 51, 16, 12, 28, 17, 214, 106, 166, 215, 246, 73, 7, 20, 232, 114],
     [114, 242, 107, 202, 32, 235, 2, 164, 141, 212, 196, 1, 101, 221, 76, 108],
     [108, 118, 236, 12, 197, 188, 175, 110, 163, 225, 144, 88, 14, 2, 195, 72],
     [72, 213, 98, 23, 6, 45, 196, 231, 213, 235, 153, 120, 82, 245, 22, 122],
     [122, 230, 78, 26, 187, 46, 241, 190, 212, 175, 55, 177, 212, 42, 110, 184],
     [184, 73, 135, 20, 203, 141, 171, 73, 9, 108, 42, 1, 96, 142, 75, 93],
     [93, 212, 184, 47, 141, 18, 238, 246, 8, 84, 15, 243, 152, 200, 127, 39],
     [39, 159, 190, 104, 26, 124, 173, 201, 132, 47, 235, 254, 198, 72, 162, 189],
     [189, 149, 94, 48, 233, 96, 191, 16, 239, 57, 236, 145, 127, 72, 137, 16],
     [16, 233, 208, 217, 243, 148, 61, 175, 123, 255, 100, 145, 82, 248, 13, 221],
     [221, 153, 117, 202, 151, 68, 90, 224, 48, 166, 49, 211, 223, 72, 100, 132],
     [132, 45, 116, 150, 93, 119, 111, 222, 84, 180, 141, 209, 68, 60, 165, 148],
     [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]]


def mul_2(num: int) -> int:
    num <<= 1
    if num.bit_length() > 8:
        num ^= 0x1c3
    return num


def mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = mul_2(a)
        b >>= 1
    return result


def L(bytes_string: bytes) -> bytes:
    result = b''
    for row in M:
        local_byte = 0
        for i in range(16):
            local_byte ^= mul(row[i], bytes_string[i])
        result += bytes([local_byte])
    return result


def invL(bytes_string: bytes) -> bytes:
    result = b''
    for row in M[::-1]:
        local_byte = 0
        for i in range(16):
            local_byte ^= mul(row[-(i+1)], bytes_string[i])
        result += bytes([local_byte])
    return result


def xor(bytes_string: bytes, key: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(bytes_string, key)])

C = [L(bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i])) for i in range(1, 33)]

def key_extend(key: bytes) -> list[bytes]:
    k_1, k_2 = key[:16], key[16:]
    k = [k_1, k_2]
    for i in range(4):
        for j in range(8):
            k_2, k_1 = k_1, xor(L(xor(k_1, C[i*8 + j])), k_2)
        k+= [k_1, k_2]
    return k

def gost_encrypt_block(bytes_string: bytes, K: list[bytes]) -> bytes:
    for i in range(9):
        bytes_string = L(xor(bytes_string, K[i]))
    return xor(bytes_string, K[9])

def gost_decrypt_block(bytes_string: bytes, K: list[bytes]) -> bytes:
    for i in range(9):
        bytes_string = invL(xor(bytes_string, K[i]))
    return xor(bytes_string, K[9])

def pad(bytes_string: bytes, block_size: int) -> list[bytes]:
    padding_byte = block_size - len(bytes_string) % block_size
    bytes_string += bytes([padding_byte] * padding_byte)
    return [bytes_string[i:i+block_size] for i in range(0, len(bytes_string), block_size)]

def unpad(bytes_string: bytes) -> bytes:
    padding_byte = bytes_string[-1]
    return bytes_string[:-padding_byte]

def ECB_encrypt(text: bytes, K: list[bytes]) -> bytes:
    ct = b''
    text = pad(text, 16)
    for block in text:
        ct += gost_encrypt_block(block, K)
    return ct

def ECB_decrypt(ctext: bytes, K: list[bytes]) -> bytes:
    text = b''
    blocks = [ctext[i:i+16] for i in range(0, len(ctext), 16)]
    for block in blocks:
        text += gost_decrypt_block(block, K[::-1])
    text = unpad(text)
    return text

key = randbytes(32)
K = key_extend(key)
with open("Database.accdb", 'rb') as f:
    text = f.read()
ctext = ECB_encrypt(text, K)
with open("db.accdb", 'wb') as f:
    f.write(ctext)