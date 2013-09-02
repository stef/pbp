#/usr/bin/env python2
import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "pbp",
    version = "0.2",
    author = "Stefan Marsiske",
    author_email = "s@ctrlc.hu",
    description = ("simple crypto tool"),
    license = "AGPLv3",
    keywords = "cryptography API NaCl libsodium",
    url = "https://github.com/stef/pbp",
    packages = ['pbp'],
    entry_points = {
       'console_scripts': [
          'pbp = pbp.main:main',
          ],
       },
    long_description=read('readme.txt'),
    install_requires = ("cffi", "scrypt", "pysodium", "SecureString"),
    classifiers = ["Development Status :: 4 - Beta",
                   "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
                   "Topic :: Security :: Cryptography",
                   "Topic :: Security",
                   ],
)
