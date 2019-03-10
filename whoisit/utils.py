import time
import hmac
import time
import hashlib
import os

from urllib.parse import urlencode, quote, parse_qsl
from base64 import b64encode, b32encode


def percent_encode(data):
    return quote(data, safe='')


def timestamp():
    return int(time.time())


def generate_nonce():
    """ 40 bytes of random data. Since twitter only accepts alphanumeric
    " characters no padding is involved.
    """
    random_bytes = os.urandom(40)
    return b32encode(random_bytes).decode()


def compute_hmac(secret, message):
    mac = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
    digest = mac.digest()
    return b64encode(digest).decode()
