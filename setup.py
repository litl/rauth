import os
import sys
import rauth

from setuptools import setup, find_packages

if sys.argv[-1] == 'test':
    nosetests = 'nosetests -v --with-coverage --cover-package=rauth'
    coverage = ('grep ^TOTAL test.log | grep 100% >/dev/null ||'
                '{ echo \'\n\033[1m\033[91mFAILURE\033[0m: '
                'Test coverage incomplete.\';'
                'exit 1; }')
    try:
        import yanc
        nosetests += ' --with-yanc --yanc-color=on'
    except ImportError:
        pass
    status = os.system('pyflakes rauth tests; '
                       'pep8 rauth tests && '
                       + nosetests + ' 2>&1 | tee -a test.log;'
                       + coverage)
    os.system('rm test.log')
    sys.exit(status)

setup(
    name='rauth',
    version=rauth.__version__,
    description='A Python library for OAuth 1.0/a, 2.0, and Ofly.',
    long_description=open('README.markdown').read(),
    author='Max Countryman',
    author_email='max@litl.com',
    url='https://github.com/litl/rauth',
    packages=find_packages(),
    install_requires=['requests>=0.12.0'],
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
    zip_safe=False,
)
