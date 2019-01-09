import requests, time, hmac, hashlib, base64

from urllib.parse import urlencode, quote

from twython import Twython


consumer_key            = "0lE48SDKD1qTYkBd6lGiLPV3Z"
consumer_secret         = "caWLLya4seNZijB7fg4XxH5a3LzPLqIKa4VOK95to1VSvMyDzT"
oauth_callback          = "https://karakays.com/callback"
oauth_signature_method  = "HMAC-SHA1"
twt_base_url            = "https://api.twitter.com"
twt_request_token_url   = twt_base_url + "/oauth/request_token"


def nonce():
    """ 32 bytes of random data encoded in base64
    """
    return "nonce-1236"


def timestamp():
    return int(time.time())


tmstamp = timestamp()

def sign(message):
    secret = quote(consumer_secret, safe='') + '&'
    print(f'secret={secret}')
    mac = hmac.new(secret.encode(), message.encode(), hashlib.sha1)
    digest = mac.digest()
    encoded = base64.b64encode(digest).decode()
    print(f'hmac={encoded}')
    return encoded


def base_string():
    query = urlencode(
            {"oauth_callback": oauth_callback,
             "oauth_consumer_key": consumer_key,
             "oauth_nonce": nonce(),
             "oauth_signature_method": oauth_signature_method,
             "oauth_timestamp": tmstamp,
             "oauth_version": "1.0"})

    print(f"query: {query}\n")

    base = quote(twt_request_token_url, safe='') + '&' + quote(query, safe='')
    base = "&".join(("POST", base))
    print(f"base_str: {base}\n")
    return base 
    

def auth_header():
    value = f"OAuth oauth_nonce=\"{nonce()}\", \
oauth_callback=\"{quote(oauth_callback, safe='')}\", \
oauth_signature_method=\"{oauth_signature_method}\", \
oauth_timestamp=\"{tmstamp}\", \
oauth_consumer_key=\"{consumer_key}\", \
oauth_signature=\"{quote(sign(base_string()), safe='')}\", \
oauth_version=\"1.0\"\
"

    print(f"auth-header: {value}\n")
    return {"Authorization": value}



print(auth_header())
r = requests.post(twt_request_token_url, headers=auth_header())
print(f"r.code={r.status_code}, r.headers={r.headers}, r.json={r.text}")


#twitter = Twython(consumer_key, consumer_secret)
#auth = twitter.get_authentication_tokens(callback_url='https://karakays.com/callback')
#print(auth)
#print(auth['auth_url'])
