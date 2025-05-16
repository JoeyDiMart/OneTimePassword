'''
Name: Joseph DiMartino
Program: Tweaked One Time Password generator, used for CSC330@UT
Date: 4.8.2025
'''
from base64 import b32decode
from datetime import datetime, timezone, timedelta
from hashlib import sha1
from hmac import HMAC


def safe_base32_decode(secret: str) -> bytes:
    secret = secret.strip().replace(" ", "").upper()
    padding_needed = (8 - len(secret) % 8) % 8
    secret += "=" * padding_needed
    return b32decode(secret, casefold=True)


def generate_otp(secret: str, time_ts: int = None, interval: int = 30, epoch_ts: int = None) -> int:
    if epoch_ts is None:
        epoch_ts = 413701950  # 1985-01-11 10:28:26 UTC
    if time_ts is None:
        time_ts = int(datetime.now(timezone.utc).timestamp())

    base32_secret = safe_base32_decode(secret)

    # Time counter using timestamps directly
    time_counter = (time_ts - epoch_ts) // interval
    counter_bytes = time_counter.to_bytes(7, byteorder="big")

    # HMAC-SHA1
    hmac_hash = HMAC(base32_secret, counter_bytes, sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    truncated = hmac_hash[offset:offset + 4]
    code = int.from_bytes(truncated, byteorder='big') & 0x7FFFFFFF
    return code % 10**7


def main():
    secret = "6R5MQOGNHBCD7CZBEHHYDEUBOJ4XWFI4HAGZJPQCFYXZQHS6BPUDTA5Y7VOKVFIIR6ZDFJ35I6UDMZBI4KLZHNJ2RLC6L7BK6KADG7I"

    current_ts = int(datetime.now(timezone.utc).timestamp())

    for i in range(-1, 2):  # previous, current, and next intervals
        shifted_ts = current_ts + i * 30
        otp = generate_otp(secret, time_ts=shifted_ts)
        print(f"OTP @ T+{i * 30}s: {otp:07d}")


main()
