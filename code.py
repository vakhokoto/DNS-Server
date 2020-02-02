import binascii

num = binascii.crc32(b'\x01\x23\x43\xa3') & 0xffffffff
print(num)