# This module just imports useful items from submodules to make
# namespacing cleaner.

__doc__ = 'Client library for OpenSRS'
__version__ = '4.3.1'
__url__ = 'https://github.com/yola/opensrs'

from opensrs.opensrsapi import OpenSRS
from opensrs import errors
