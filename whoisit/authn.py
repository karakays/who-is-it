import logging

from .config import *
from .utils import *
from whoisit import authentication


logger = logging.getLogger(__name__)


"""
Cover all steps of 3 legged authn
state pattern
def next() method that covers all steps
"""
class token_authn_context:
    pass


"""
base: oauth_consumer_key, oauth_consumer_secret
request_token: callback
access_token: oauth_token, oauth_token_secret, oauth_verifier

api call: oauth_token (access token)
"""
class authn_request_context:
    """
    include body only if content-type=x-www-form-urlencoded
    """
    # TODO add query params
    def __init__(self, method, endpoint, body=None):
        self.method = method
        self.endpoint = endpoint
        self.body = body
        self.nonce = percent_encode(generate_nonce())
        self.timestamp = timestamp()


    def base_string(self):
        params = [("oauth_consumer_key", authentication.key),
                  ("oauth_nonce", self.nonce),
                  ("oauth_signature_method", OAUTH_SIGNATURE_METHOD),
                  ("oauth_timestamp", self.timestamp),
                  ("oauth_token", authentication.token),
                  ("oauth_version", OAUTH_VERSION)]

        if self.body:
            pairs = self.body.split('&')
            for p in pairs:
                key, value = p.split('=')
                params.append((percent_encode(key), percent_encode(value)))

        # canonicalize
        params.sort(key = lambda p: p[0])

        normalized_params = urlencode(params)

        logger.debug('normalized_params=%s', normalized_params)
        base = percent_encode(self.endpoint) + '&' + percent_encode(normalized_params)
        base = "&".join((self.method, base))
        logger.debug('base_str=%s', base)
        return base


    def sign(self, base_str):
        mac = compute_hmac(authentication.secret, base_str)
        return percent_encode(mac)


    def get_auth_header(self):
        base_str = self.base_string()
        signature = self.sign(base_str)
        return {'Authorization': f"OAuth oauth_nonce=\"{self.nonce}\", \
oauth_token=\"{percent_encode(authentication.token)}\", \
oauth_signature_method=\"{OAUTH_SIGNATURE_METHOD}\", \
oauth_timestamp=\"{self.timestamp}\", \
oauth_consumer_key=\"{authentication.key}\", \
oauth_signature=\"{signature}\", \
oauth_version=\"{OAUTH_VERSION}\"\
"}

    def authenticate(self):
        pass
