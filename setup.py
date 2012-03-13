import os
import sys
import webauth

from setuptools import setup, find_packages

if sys.argv[-1] == 'test':
    os.system('pyflakes webauth; '
              'pep8 webauth && '
              'nosetests --with-coverage --cover-package=webauth')
    sys.exit()

setup(
    name='webauth',
    version=webauth.__version__,
    description='A Python Requests hook providing OAuth 1.0/a support.',
    long_description=open('README.markdown'),
    author='Max Countryman', # this is just a stand-in don't know what's preferred
    author_email='max@litl.com', # ditto
    url='https://github.com/litl/webauth',
    packages=find_packages(),
    install_requires=['requests>=0.10.0'],
    license='MIT',
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ),
    zip_safe=False,
)
