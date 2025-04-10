'''
Name: Joseph DiMartino
Program: Tweaked One Time Password generator, used for CSC330@UT
Date: 4.8.2025
'''
from base64 import b32decode
from datetime import datetime
from hashlib import sha1, sha256, md5
from hmac import HMAC

secret = "EBXEC5XL7ATNXKE2V6N34C2YURRFGWJH"
bytes_secret = secret.encode("utf-8")
base32_secret = b32decode(bytes_secret)
current_time = datetime.now()
OTP_interval = 30  # set interval to 30 seconds
custom_epoch = datetime(2024, 1, 1, 0, 0, 0) # Y, M, D, H, M, S
time_counter = int((current_time - custom_epoch).total_seconds() // OTP_interval)
time_counter = time_counter.to_bytes(8, byteorder="big")

# hash2 = HMAC(bytes_secret, time_counter, sha1) # saving if needed to get a hash with the bytes of the secret
hash = HMAC(base32_secret, time_counter, sha1).hexdigest()
offset = int(hash[-1:], 16)  # change the hex offset to decimal
print("sha1 hash: ", hash)
print("offset: ", offset)
four_bytes = bin(int(hash[offset:offset+8], 16)).replace("0b", "").zfill(8)  # 8 is for 4 bytes to be read from offset
four_bytes = "0" + four_bytes[1:]  # replace the highest order bit
print("Binary of the 4 bytes taken: ", four_bytes)
print("Decimal of the 4 bytes taken: ", int(four_bytes, 2))
OTP = str(int(four_bytes, 2))[-6:]
print("OTP: ", OTP)



'''
# saved for in needed later 
if len(base32secret) % 8 != 0:
    while len(base32secret) % 8 != 0:
        base32secret += "="
len_base32secret = len(base32secret)
'''