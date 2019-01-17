import logging
import os, requests, time, hmac, hashlib

from urllib.parse import urlencode, quote, parse_qsl
from base64 import b64encode, b32encode


logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

# read from ENV VAR here
oauth_consumer_key      = "0lE48SDKD1qTYkBd6lGiLPV3Z"
oauth_consumer_secret   = "caWLLya4seNZijB7fg4XxH5a3LzPLqIKa4VOK95to1VSvMyDzT"
oauth_access_token        = "60745511-3C9wtHpkURxgSDsPg4cNGfm409bPRF6gbJc76u2s9"
oauth_access_token_secret = "O6Pul5zdq0OhK08KDS13PV57sBDPARlmRIwd0D3PLTbxW"
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

authn = None


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
        self.secret = quote(oauth_consumer_secret, safe='') + '&' + quote(oauth_token_secret, safe='')
        self.token = oauth_token
        self.nonce = quote(generate_nonce(), safe='')
        self.timestamp = timestamp()


    # TODO: sort this out
    def base_string(self):
        query = urlencode(
                {"oauth_consumer_key": self.key,
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
class authn_context:
    def __init__(self, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret):
        """
        oauth_token=returned from request_token response
        oauth_token_secret=returned from request_token response
        oauth_verifier=returned from resource owner auth phase
        """
        self.key = oauth_consumer_key
        self.secret = quote(oauth_consumer_secret, safe='') + \
                            '&' + quote(oauth_token_secret, safe='')
        self.token = oauth_token
        self.nonce = quote(generate_nonce(), safe='')
        self.timestamp = timestamp()


    def base_string(self, http_method, request_endpoint):
        oauth_params = [("oauth_consumer_key", self.key),
                        ("oauth_nonce", self.nonce),
                        ("oauth_signature_method", oauth_signature_method),
                        ("oauth_timestamp", self.timestamp),
                        ("oauth_token", self.token),
                        ("oauth_version", oauth_version)]

        # sort by keys lexically
        oauth_params.sort(key = lambda p: p[0])

        query = urlencode(oauth_params)

        logger.debug('query=%s', query)
        base = quote(request_endpoint, safe='') + '&' + quote(query, safe='')
        base = "&".join((http_method, base))
        logger.debug('base_str=%s', base)
        return base

    def sign(self, base_str):
        return quote(compute_hmac(self.secret, base_str), safe='')


    def get_authz_header(self, http_method, request_endpoint):
        base_str = self.base_string(http_method, request_endpoint)
        signature = self.sign(base_str)
        return {'Authorization': f"OAuth oauth_nonce=\"{self.nonce}\", \
oauth_token=\"{quote(self.token, safe='')}\", \
oauth_signature_method=\"{oauth_signature_method}\", \
oauth_timestamp=\"{self.timestamp}\", \
oauth_consumer_key=\"{self.key}\", \
oauth_signature=\"{signature}\", \
oauth_version=\"{oauth_version}\"\
"}

    def authenticate(self):
        pass

def request_temp_token(consumer_key, consumer_key_secret, callback_url):
    request = temp_cred_request(consumer_key, consumer_secret, callback_url)
    headers = {'Authorization': request.auth_header()}
    api_response = requests.post(twt_request_token_url, headers=headers)

    if api_response.status_code != 200:
        logger.error('No success from %s: code=%s, r.headers=%s, r.body=%s',
                     twt_request_token_url, api_response.status_code,
                     api_response.headers, api_response.text)
    #if oauth_cb_confirmed == 'false':
    token, token_secret, cb_confirmed = [ e[1] for e in
                                         parse_qsl(api_response.text) ]
    return (token, token_secret)


def authorize_user(request_token):
    oauth_verifier = input(f'''Go to {twt_authorize_url}?
                           request_token={oauth_token} and get the
                           oauth_verifier: ''').strip()

    return oauth_verifier


def request_access_token(consumer_key, consumer_secret, request_token,
                         request_token_secret, oauth_verifier):
    request = token_cred_request(consumer_key, consumer_secret, request_token,
                                 request_token_secret, oauth_verifier)
    headers = {'Authorization': request.auth_header()}

    api_response = requests.post(twt_access_token_url, headers=headers)

    if api_response.status_code != 200:
        logger.error('No success from %s: code=%s, r.headers=%s, r.body=%s',
                     twt_access_token_url, api_response.status_code,
                     api_response.headers, api_response.text)

    at_res = parse_qsl(api_response.text)

    token, token_secret, user_id, screen_name = [ e[1] for e in \
                                                 parse_qsl(api_response.text) ]

    logger.debug("access_token=%s, access_token_secret=%s, user_id=%s",
                 token, token_secret, user_id);


def authenticated(func):
    def wrapper_authenticated(*args, **kwargs):
        if authn is None:
            raise Error('not authenticated')
        return func(*args, **kwargs)
    return wrapper_authenticated


@authenticated
def get_follower_ids():
    response = requests.get(twt_followers_url,
                            headers=authn.get_authz_header('GET',
                                                           twt_followers_url))
    follower_ids = response.json()['ids']
    return follower_ids


authn = authn_context(oauth_consumer_key, oauth_consumer_secret,
                      oauth_access_token, oauth_access_token_secret)

followers = get_follower_ids()
print(followers)
