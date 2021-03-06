import logging
import sched
import time

from . import twt


logger = logging.getLogger(__name__)

followers = set()


def authenticated(func):
    global authentication
    def wrapper_authenticated(*args, **kwargs):
        if authentication is None:
            raise Error('not authenticated')
        return func(*args, **kwargs)
    return wrapper_authenticated


def check_followers():
    try:
        account = twt.get_account_details()
        unfollowers = followers - twt.get_follower_ids()
        logger.info("%s people unfollowed you", len(unfollowers))
        for uf in unfollowers:
            twt.send_direct_message(account["id"], f"{uf} unfollowed you :(")
        else:
            logger.info("No unfollowers, yay!")
    except twt.TwtError:
        pass


def run():
    scheduler = sched.scheduler(time.time, time.sleep)
    while True:
        scheduler.enter(5, 1, check_followers)
        scheduler.run()
