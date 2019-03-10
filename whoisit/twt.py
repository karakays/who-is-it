import logging

import requests

from .config import *
from .authn import authn_request_context

# from app import authenticated

logger = logging.getLogger(__name__)

# @authenticated
def get_follower_ids():
    authn_ctx = authn_request_context('GET', TWT_FOLLOWERS_URL)
    response = requests.get(authn_ctx.endpoint,
                            headers=authn_ctx.get_authz_header())
    logger.debug("%s returned headers=%s, body=%s",
                 TWT_FOLLOWERS_URL, response.headers, response.text)

    if response.ok:
        return set(response.json()['ids'])
    else:
        logger.warn(response.status_code, response.content)
        raise RuntimeError()


# @authenticated
def send_direct_message(recipient_id, message):
    authn_ctx = authn_request_context('POST', TWT_DIRECT_MSG_URL)
    payload = f'''{"event":
        {"type": "message_create",
         "message_create":
            {"target": {"recipient_id": "{recipient_id}"},
                "message_data": {"text": "{message}"}}}} '''

    response = requests.post(TWT_DIRECT_MSG_URL,
                             headers=authn_ctx.get_authz_header(),
                             data=payload)

    logger.debug("%s returned headers=%s, body=%s",
                 TWT_DIRECT_MSG_URL, response.headers, response.text)

    if not response.ok:
        logger.warn(response.status_code, response.content)


def get_account_details():
    authn_ctx = authn_request_context('GET', TWT_GET_ACCOUNT_URL)
    response = requests.get(authn_ctx.endpoint,
                            headers=authn_ctx.get_authz_header())
    logger.debug("%s returned headers=%s, body=%s",
                 TWT_GET_ACCOUNT_URL, response.headers, response.text)

    if response.ok:
        return response.json()
