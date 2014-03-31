import re

from setuptools import find_packages, setup

init_py = open('opensrs/__init__.py').read()
metadata = dict(re.findall("__([a-z]+)__ = '([^']+)'", init_py))

setup(
    name='opensrs',
    version=metadata['version'],
    description=metadata['doc'],
    author='Yola',
    author_email='engineers@yola.com',
    license='MIT (Expat)',
    url=metadata['url'],
    packages=find_packages()
)
