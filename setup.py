import os
import sys
import rauth

from setuptools import setup, find_packages

if sys.argv[-1] == 'test':
    nosetests = 'nosetests -v --with-coverage --cover-package=rauth'
    try:
        import yanc
        nosetests += ' --with-yanc'
    except ImportError:
        pass
    os.system('pyflakes rauth tests; '
              'pep8 rauth tests && '
              + nosetests)
    sys.exit()

setup(
    name='rauth',
    version=rauth.__version__,
    description='A Python Requests hook providing OAuth 1.0/a support.',
    long_description=open('README.markdown').read(),
    author='Max Countryman', # this is just a stand-in don't know what's preferred
    author_email='max@litl.com', # ditto
    url='https://github.com/litl/rauth',
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
