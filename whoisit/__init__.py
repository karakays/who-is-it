import logging

from .app import main
from ._version import __version__

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
