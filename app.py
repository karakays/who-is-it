import config
import logging
import sched
import time

import twitter

from utils import *
from authn import authn_details


logger = logging.getLogger(__name__)

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

authentication = authn_details(config.CONSUMER_KEY, config.CONSUMER_SECRET,
                               config.ACCESS_TOKEN, config.ACCESS_TOKEN_SECRET)
followers = set()

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
    global authentication
    def wrapper_authenticated(*args, **kwargs):
        if authentication is None:
            raise Error('not authenticated')
        return func(*args, **kwargs)
    return wrapper_authenticated


def run():
    global followers
    unfollowers = followers - twitter.get_follower_ids(12)
    print(f"Unfollowed: {len(unfollowers)}")
    #send_message()


def main():
    run()
    #scheduler = sched.scheduler(time.time, time.sleep)
    #while True:
        #scheduler.enter(5, 1, run)
        #scheduler.run()


if __name__ == '__main__':
    main()
