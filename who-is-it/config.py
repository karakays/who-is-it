import json, os

OAUTH_CALLBACK          = "https://karakays.com/callback"

OAUTH_SIGNATURE_METHOD  = "HMAC-SHA1"
OAUTH_VERSION           = '1.0'

TWT_BASE_URL            = "https://api.twitter.com"
TWT_REQUEST_TOKEN_URL   = TWT_BASE_URL + "/oauth/request_token"
TWT_AUTHORIZE_URL       = TWT_BASE_URL + "/oauth/authorize"
TWT_ACCESS_TOKEN_URL    = TWT_BASE_URL + "/oauth/access_token"
TWT_FOLLOWERS_URL       = TWT_BASE_URL + "/1.1/followers/ids.json"
TWT_DIRECT_MSG_URL      = TWT_BASE_URL + "/1.1/direct_messages/events/new.json"

CONSUMER_KEY            = None
CONSUMER_SECRET         = None
ACCESS_TOKEN            = None
ACCESS_TOKEN_SECRET     = None


def read_config_file():
    global CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_TOKEN_SECRET

    with open('keys.json', 'r') as jsonfile:
        config = json.load(jsonfile)['credentials']

        CONSUMER_KEY = config['consumer_key']
        if CONSUMER_KEY is None: raise ValueError('consumer_key not set')

        CONSUMER_SECRET = config['consumer_secret']
        if CONSUMER_SECRET is None: raise ValueError('consumer_secret not set')

        ACCESS_TOKEN = config['access_token']
        if ACCESS_TOKEN is None: raise ValueError('access_token not set')

        ACCESS_TOKEN_SECRET = config['access_token_secret']
        if ACCESS_TOKEN_SECRET is None: raise ValueError('access_token_secret not set')


def read_env_vars():
    global CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_TOKEN_SECRET

    CONSUMER_KEY = os.environ.get('CONSUMER_KEY')
    if CONSUMER_KEY is None: raise ValueError('consumer_key not set')

    CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET')
    if CONSUMER_SECRET is None: raise ValueError('consumer_secret not set')

    ACCESS_TOKEN = os.environ.get('ACCESS_TOKEN')
    if ACCESS_TOKEN is None: raise ValueError('access_token not set')

    ACCESS_TOKEN_SECRET = os.environ.get('ACCESS_TOKEN_SECRET')
    if ACCESS_TOKEN_SECRET is None: raise ValueError('access_token_secret not set')

try:
    read_config_file()
except (ValueError, FileNotFoundError) as e:
    # fallback to environment variables
    read_env_vars()
