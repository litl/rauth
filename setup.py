'''
    rauth
    -----

    A simple Python OAuth 1.0/a, OAuth 2.0, and Ofly consumer library built on
    top of Requests.

    Links
    `````
    * `documentation <https://rauth.readthedocs.org/en/latest/>`_
    * `development version <https://github.com/litl/rauth>`_
'''

import os
import sys

from setuptools import setup, find_packages

about = {}
with open('rauth/__about__.py') as f:
    exec(f.read(), about)

if sys.argv[-1] == 'test':
    status = os.system('make check')
    status >>= 8
    sys.exit(status)

install_requires = ['requests==1.2.3']
if sys.version_info[0] == 2 and sys.version_info[1] < 7:
    install_requires.append('unittest2>=0.5.1')

classifiers = ['Development Status :: 5 - Production/Stable',
               'Intended Audience :: Developers',
               'Programming Language :: Python',
               'License :: OSI Approved :: MIT License',
               'Natural Language :: English',
               'Operating System :: OS Independent',
               'Operating System :: MacOS',
               'Operating System :: POSIX',
               'Operating System :: POSIX :: Linux',
               'Programming Language :: Python',
               'Programming Language :: Python :: 2.6',
               'Programming Language :: Python :: 2.7',
               'Programming Language :: Python :: 3.3',
               'Programming Language :: Python :: Implementation',
               'Programming Language :: Python :: Implementation :: CPython',
               'Topic :: Internet :: WWW/HTTP',
               'Topic :: Software Development :: Libraries :: Python Modules',
               'Topic :: Utilities']

setup(name=about['__title__'],
      version=about['__version__'],
      description='A Python library for OAuth 1.0/a, 2.0, and Ofly.',
      long_description=__doc__,
      author=about['__author__'],
      author_email='max@litl.com',
      url='https://github.com/litl/rauth',
      packages=find_packages(),
      install_requires=install_requires,
      license=about['__license__'],
      keywords='oauth oauth2 rauth requests',
      classifiers=classifiers,
      zip_safe=False)
