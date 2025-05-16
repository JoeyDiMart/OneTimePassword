'''
Name: Joseph DiMartino
Program: Tweaked One Time Password generator, used for CSC330@UT
Date: 4.8.2025
'''
from base64 import b32decode
from datetime import datetime, timezone, timedelta
from hashlib import sha1, sha256, md5
from hmac import HMAC


def safe_base32_decode(secret: str) -> bytes:
    secret = secret.strip().replace(" ", "").upper()
    padding_needed = (8 - len(secret) % 8) % 8
    secret += "=" * padding_needed
    return b32decode(secret, casefold=True)


def generate_otp(secret: str, time: datetime = None, interval: int = 30, epoch: datetime = None) -> int:
    if not epoch:
        epoch = datetime(1975, 12, 16, 1, 33, 12, tzinfo=timezone.utc)  # HERE PUT EPOCH TIME
    if not time:
        time = datetime.now(timezone.utc)

    base32_secret = safe_base32_decode(secret)

    # Time counter
    time_counter = int((time - epoch).total_seconds() // interval)
    counter_bytes = time_counter.to_bytes(7, byteorder="big")

    # HMAC-SHA1
    hmac_hash = HMAC(base32_secret, counter_bytes, sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    truncated = hmac_hash[offset:offset + 4]
    code = int.from_bytes(truncated, byteorder='big') & 0x7FFFFFFF
    return code % 10 ** 7


def main():
    secret = "DQ45V5NVDGZCTKGW746523OZGKWDMGN7RZUNTV2E6547XWUI42BIXY2GX7XZ32CD3NZHCSGROOX27YDAQPJEQEKRXUXZH7XUCG4N22Y"
    for i in range(-1, 2):  # get OTPs for previous, current, and next intervals
        time_shift = datetime.now(timezone.utc) + i * timedelta(seconds=30)
        otp = generate_otp(secret, time=time_shift)
        print(f"OTP @ T+{i * 30}s: {otp:07d}")


main()

# <!-- Shhhh! It's a secret! 6R5MQOGNHBCD7CZBEHHYDEUBOJ4XWFI4HAGZJPQCFYXZQHS6BPUDTA5Y7VOKVFIIR6ZDFJ35I6UDMZBI4KLZHNJ2RLC6L7BK6KADG7I -->