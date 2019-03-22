OAUTH_CALLBACK          = "https://karakays.com/callback"

OAUTH_SIGNATURE_METHOD  = "HMAC-SHA1"
OAUTH_VERSION           = '1.0'

TWT_BASE_URL            = "https://api.twitter.com"
TWT_REQUEST_TOKEN_URL   = TWT_BASE_URL + "/oauth/request_token"
TWT_AUTHORIZE_URL       = TWT_BASE_URL + "/oauth/authorize"
TWT_ACCESS_TOKEN_URL    = TWT_BASE_URL + "/oauth/access_token"
TWT_FOLLOWERS_URL       = TWT_BASE_URL + "/1.1/followers/ids.json"
TWT_DIRECT_MSG_URL      = TWT_BASE_URL + "/1.1/direct_messages/events/new.json"
TWT_GET_ACCOUNT_URL     = TWT_BASE_URL + "/1.1/account/verify_credentials.json"
