import json
import logging
import os

from ._version import __version__
from .utils import percent_encode


logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)


class authn_details:

    def __init__(self, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret):
        self.key = oauth_consumer_key
        self.token = oauth_token
        self.secret = percent_encode(oauth_consumer_secret) + '&' + \
                      percent_encode(oauth_token_secret)


def read_credentials():
    credentials = (os.environ.get('CONSUMER_KEY'),
                    os.environ.get('CONSUMER_SECRET'),
                    os.environ.get('ACCESS_TOKEN'),
                    os.environ.get('ACCESS_TOKEN_SECRET'))

    if not all(credentials):
        try:
            with open('keys.json', 'r') as jsonfile:
                keys = json.load(jsonfile)['credentials']

                credentials = (keys['consumer_key'],
                                keys['consumer_secret'],
                                keys['access_token'],
                                keys['access_token_secret'])

                if not all(credentials):
                    raise ValueError('Keys not set!')
        except (FileNotFoundError) as e:
            raise ValueError('Keys not set!')

    return authn_details(credentials[0], credentials[1],
                         credentials[2], credentials[3])


authentication = read_credentials()
