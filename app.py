import logging
import os, requests, time, hmac, hashlib

from urllib.parse import urlencode, quote, parse_qsl
from base64 import b64encode, b32encode


logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

# Applicatoin identifier
oauth_consumer_key      = "0lE48SDKD1qTYkBd6lGiLPV3Z"
oauth_consumer_secret   = "caWLLya4seNZijB7fg4XxH5a3LzPLqIKa4VOK95to1VSvMyDzT"
oauth_callback          = "https://karakays.com/callback"

oauth_signature_method  = "HMAC-SHA1"
oauth_version           = '1.0'

twt_base_url            = "https://api.twitter.com"
twt_request_token_url   = twt_base_url + "/oauth/request_token"
twt_authorize_url       = twt_base_url + "/oauth/authorize"
twt_access_token_url    = twt_base_url + "/oauth/access_token"

twt_followers_url       = twt_base_url + "/1.1/followers/ids.json"

OAUTH_CONSUMER_KEY_KEY  = 'oauth_consumer_key'
OAUTH_CALLBACK_KEY      = 'oauth_callback'
OAUTH_TOKEN_KEY         = 'oauth_token'
OAUTH_TOKEN_SECRET_KEY  = 'oauth_token_secret'
OAUTH_VERIFIER_KEY      = 'oauth_verifier'


def generate_nonce():
    """ 40 bytes of random data. Since twitter only accepts alphanumeric
    " characters no padding is involved.
    """
    random_bytes = os.urandom(40)
    return b32encode(random_bytes).decode()


def timestamp():
    return int(time.time())


def compute_hmac(secret, message):
    mac = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
    digest = mac.digest()
    return b64encode(digest).decode()


class temp_cred_request:
    """
    oauth_rt
    Temporary credentials request
    """
    def __init__(self, oauth_key, oauth_secret, oauth_cb):
        self.consumer_key = oauth_key
        self.consumer_secret = quote(oauth_secret, safe='') + '&'
        self.callback_url = oauth_cb
        self.nonce = quote(generate_nonce(), safe='')
        self.timestamp = timestamp()


    # TODO: sort this out
    def base_string(self):
        query = urlencode(
                {"oauth_callback": self.callback_url,
                 "oauth_consumer_key": self.consumer_key,
                 "oauth_nonce": self.nonce,
                 "oauth_signature_method": oauth_signature_method,
                 "oauth_timestamp": self.timestamp,
                 "oauth_version": oauth_version})
        logger.debug('Query calculated: %s', query)
        base = quote(twt_request_token_url, safe='') + '&' + quote(query, safe='')
        base = "&".join(("POST", base))
        logger.debug('Base string calculated: %s', base)
        return base 


    @property
    def signature(self):
        return quote(compute_hmac(self.consumer_secret, self.base_string()), safe='')


    def auth_header(self):
        return f"OAuth oauth_nonce=\"{self.nonce}\", \
oauth_callback=\"{quote(self.callback_url, safe='')}\", \
oauth_signature_method=\"{oauth_signature_method}\", \
oauth_timestamp=\"{self.timestamp}\", \
oauth_consumer_key=\"{self.consumer_key}\", \
oauth_signature=\"{self.signature}\", \
oauth_version=\"{oauth_version}\"\
"


class token_cred_request:
    """
    oauth_at
    Token credentials request
    """
    def __init__(self, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret, oauth_verifier):
        """
        oauth_token=returned from request_token response
        oauth_token_secret=returned from request_token response
        oauth_verifier=returned from resource owner auth phase
        """
        self.key = oauth_consumer_key
        self.secret = quote(oauth_consumer_secret + '&' + oauth_token_secret, safe='')
        self.token = oauth_token
        self.verifier = oauth_verifier
        self.nonce = quote(generate_nonce(), safe='')
        self.timestamp = timestamp()


    # TODO: sort this out
    def base_string(self):
        query = urlencode(
                { "oauth_consumer_key": self.key,
                 "oauth_nonce": self.nonce,
                 "oauth_signature_method": oauth_signature_method,
                 "oauth_token": self.token,
                 "oauth_timestamp": self.timestamp,
                 "oauth_verifier": self.verifier,
                 "oauth_version": oauth_version})

        logger.debug('Query calculated: %s', query)
        base = quote(twt_access_token_url, safe='') + '&' + quote(query, safe='')
        base = "&".join(("POST", base))
        logger.debug('Base string calculated: %s', base)
        return base 


    @property
    def signature(self):
        return quote(compute_hmac(self.secret, self.base_string()), safe='')


    def auth_header(self):
        return f"OAuth oauth_nonce=\"{self.nonce}\", \
oauth_token=\"{quote(self.token, safe='')}\", \
oauth_signature_method=\"{oauth_signature_method}\", \
oauth_timestamp=\"{self.timestamp}\", \
oauth_consumer_key=\"{self.key}\", \
oauth_signature=\"{self.signature}\", \
oauth_verifier=\"{self.verifier}\", \
oauth_version=\"{oauth_version}\"\
"


class authn_request:
    """
    oauth_at
    Token credentials request
    """
    def __init__(self, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret):
        """
        oauth_token=returned from request_token response
        oauth_token_secret=returned from request_token response
        oauth_verifier=returned from resource owner auth phase
        """
        self.key = oauth_consumer_key
        self.secret = quote(oauth_consumer_secret + '&' + oauth_token_secret, safe='')
        self.token = oauth_token
        self.nonce = quote(generate_nonce(), safe='')
        self.timestamp = timestamp()


    # TODO: sort this out
    def base_string(self):
        query = urlencode(
                { "oauth_consumer_key": self.key,
                 "oauth_nonce": self.nonce,
                 "oauth_signature_method": oauth_signature_method,
                 "oauth_timestamp": self.timestamp,
                 "oauth_token": self.token,
                 "oauth_version": oauth_version})

        logger.debug('Query calculated: %s', query)
        base = quote(twt_followers_url, safe='') + '&' + quote(query, safe='')
        base = "&".join(("GET", base))
        logger.debug('Base string calculated: %s', base)
        return base 


    @property
    def signature(self):
        return quote(compute_hmac(self.secret, self.base_string()), safe='')


    def auth_header(self):
        return f"OAuth oauth_nonce=\"{self.nonce}\", \
oauth_token=\"{quote(self.token, safe='')}\", \
oauth_signature_method=\"{oauth_signature_method}\", \
oauth_timestamp=\"{self.timestamp}\", \
oauth_consumer_key=\"{self.key}\", \
oauth_signature=\"{self.signature}\", \
oauth_version=\"{oauth_version}\"\
"



"""
base: oauth_consumer_key, oauth_consumer_secret
request_token: callback
access_token: oauth_token, oauth_token_secret, oauth_verifier

api call: oauth_token (access token)
"""
class twt_authn:
    def __init__(self, oauth_consumer_key, oauth_consumer_secret, kwargs):
        """
        oauth_token=returned from request_token response
        oauth_token_secret=returned from request_token response
        oauth_verifier=returned from resource owner auth phase
        """
        self.key = oauth_consumer_key
        self.secret = quote(oauth_consumer_secret + '&' + kwargs.get(oauth_token_secret, ''), safe='')
        self.token = oauth_token
        self.verifier = oauth_verifier
        self.nonce = quote(generate_nonce(), safe='')
        self.timestamp = timestamp()
        self.params = kwargs


    def base_string(self):
        oauth_params = [("oauth_consumer_key", self.key),
                        ("oauth_nonce", self.nonce),
                        ("oauth_signature_method", oauth_signature_method),
                        ("oauth_timestamp", self.timestamp),
                        ("oauth_version", oauth_version)]

        #if OAUTH_TOKEN_KEY in self.params:
        #    oauth_params.append((OAUTH_TOKEN_KEY, params.get(OAUTH_TOKEN_KEY))

        #if OAUTH_VERIFIER_KEY in self.params:
        #    oauth_params.append((OAUTH_VERIFIER_KEY, params.get(OAUTH_VERIFIER_KEY))

        #if OAUTH_CALLBACK_KEY in self.params:
        #    oauth_params.append((OAUTH_CALLBACK_KEY, params.get(OAUTH_CALLBACK_KEY))

        oauth_params.sort(key = lambda p: p[0])

        query = urlencode(oauth_params)

        logger.debug('Query calculated: %s', query)
        base = quote(twt_access_token_url, safe='') + '&' + quote(query, safe='')
        base = "&".join(("POST", base))
        logger.debug('Base string calculated: %s', base)
        return base 


rt_req = temp_cred_request(oauth_consumer_key, oauth_consumer_secret, oauth_callback)

rt_headers = {'Authorization': rt_req.auth_header()}

r = requests.post(twt_request_token_url, headers=rt_headers)

if r.status_code != 200:
    logger.error('No success from %s: code=%s, r.headers=%s, r.body=%s', twt_request_token_url, r.status_code, r.headers, r.text)

rt_res = parse_qsl(r.text)

oauth_token, oauth_token_secret, oauth_cb_confirmed = [ e[1] for e in rt_res ]

#if oauth_cb_confirmed == 'false':

oauth_verifier = input(f'Please go to {twt_authorize_url}?oauth_token={oauth_token} and get the oauth_verifier: ').strip()

at_req = token_cred_request(oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret, oauth_verifier)

at_headers = {'Authorization': at_req.auth_header()}

r = requests.post(twt_access_token_url, headers=at_headers)

if r.status_code != 200:
    logger.error('No success from %s: code=%s, r.headers=%s, r.body=%s', twt_access_token_url, r.status_code, r.headers, r.text)

print("access token here:" + r.text)

at_res = parse_qsl(r.text)

oauth_token, oauth_token_secret, user_id, screen_name = [ e[1] for e in at_res ]

authn_req = authn_request(oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret)

authn_headers = {'Authorization': authn_req.auth_header()}

print(authn_headers)

r = requests.get(twt_followers_url, headers=authn_headers)
print(r.status_code, r.headers, r.text)
logger.info('response %s: code=%s, r.headers=%s, r.body=%s', twt_request_token_url, r.status_code, r.headers, r.text)
