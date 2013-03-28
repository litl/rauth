import os
import sys

from rauth import __version__

from setuptools import setup, find_packages

if sys.argv[-1] == 'test':
    status = os.system('make check')
    status >>= 8
    sys.exit(status)

install_requires = ['requests==1.1.0']
if sys.version_info[0] == 2 and sys.version_info[1] < 7:
    install_requires.append('unittest2>=0.5.1')

setup(name='rauth',
      version=__version__,
      description='A Python library for OAuth 1.0/a, 2.0, and Ofly.',
      long_description=open('README.markdown').read(),
      author='Max Countryman',
      author_email='max@litl.com',
      url='https://github.com/litl/rauth',
      packages=find_packages(),
      install_requires=install_requires,
      license='MIT',
      classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ),
    zip_safe=False)
