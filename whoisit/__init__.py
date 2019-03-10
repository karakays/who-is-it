import logging
print("hey")
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
print("hey1")

#from . import config
from .app import main
print("hey3")
#from . import authn
#from . import twt
#from . import utils
