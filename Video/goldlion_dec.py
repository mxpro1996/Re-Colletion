import hashlib
from Crypto.Cipher import AES
from pathlib import Path
import sys

def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def aes_decrypt_ecb(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(data)

def generate_block(pos: int) -> bytes:
    def step(val): return (val >> 1) ^ 0x80000061 if val & 1 else val >> 1
    part0 = (pos >> 13) & 0x7FFFFFFF
    if pos & 0x1000:
        part0 ^= 0x80000061
    u32 = [part0]
    for _ in range(3):
        u32.append(step(u32[-1]))
    return b''.join(x.to_bytes(4, 'little') for x in u32)

def dataFixer(data: bytes, pos: int, key: bytes) -> bytes:
    block = generate_block(pos)
    xor_block = AES.new(key, AES.MODE_ECB).encrypt(block)
    return bytes(b ^ xor_block[i % 16] for i, b in enumerate(data))

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} input.bin output.bin")
        return

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    
    android_id = b"b80980f702402a0ab"
    md5_key = md5(android_id)

    encrypted_user_key = bytes([
        0xa3, 0x94, 0x4e, 0x3a,
        0xc8, 0x07, 0xb9, 0x9c,
        0x57, 0x72, 0x3c, 0x80,
        0x2b, 0x64, 0x32, 0xd9,
    ])
    user_key = aes_decrypt_ecb(encrypted_user_key, md5_key)

    with input_path.open("rb") as f_in, output_path.open("wb") as f_out:
        pos = 0
        while True:
            chunk = f_in.read(128)
            if not chunk:
                break
            fixed = dataFixer(chunk, pos, user_key)
            f_out.write(fixed)
            pos += len(chunk)

    print(f"✅ Dec Finished：{output_path}")

if __name__ == "__main__":
    main()
