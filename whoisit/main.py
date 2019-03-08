import config
import logging
import sched
import time

import twitter

from utils import *
from authn import authn_details


logger = logging.getLogger(__name__)

followers = set()


def authenticated(func):
    global authentication
    def wrapper_authenticated(*args, **kwargs):
        if authentication is None:
            raise Error('not authenticated')
        return func(*args, **kwargs)
    return wrapper_authenticated


def run():
    unfollowers = followers - twitter.get_follower_ids(12)
    logger.info("%s people unfollowed you", len(unfollowers))
    for uf in unfollowers:
        twitter.send_direct_message(12, f"{uf} unfollowed you :(")


def main():
    scheduler = sched.scheduler(time.time, time.sleep)
    while True:
        scheduler.enter(5, 1, run)
        scheduler.run()


if __name__ == '__main__':
    main()
