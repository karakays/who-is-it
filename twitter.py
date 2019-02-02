import requests
import config

from authn import authn_request_context

from app import authenticated


@authenticated
def get_follower_ids(ids, ctx):
    #authn_ctx = authn_request_context('GET', config.TWT_FOLLOWERS_URL)
    #response = requests.get(authn_ctx.endpoint,
    #                        headers=authn_ctx.get_authz_header())
    #print(response.headers)
    #return set(response.json()['ids'])
    print(ids)


@authenticated
def send_direct_message(recipient_id, message):
    authn_ctx = authn_request_context('POST', config.TWT_DIRECT_MSG_URL)
    payload = '{"event": {"type": "message_create", "message_create": {"target": {"recipient_id": "60745511"}, "message_data": {"text": "Hello World!"}}}}'
    response = requests.post(config.TWT_DIRECT_MSG_URL,
                             headers=authn_ctx.get_authz_header(),
                             data=payload)
    print(response.headers)
    print(response.text)



payload = '''{
    "event": {
            "type": "message_create",
            "message_create": {
                "target": {
                    "recipient_id": "60745511"
                },
            "message_data": {
                "text": "Hello World!"
            }
        }
    }}'''

class message:
    #class message_create
    def __init__(self, recipient_id, text):
        self.type = 'message_create'
