import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='scirius',
    version='3.8.0',
    packages=['scirius','rules','suricata', 'accounts', 'viz'],
    scripts=['manage.py'],
    include_package_data=True,
    description='A web interface to manage Suricata rulesets',
    long_description=README,
    url='https://www.stamus-networks.com/open-source/#scirius',
    author='Eric Leblond',
    author_email='eleblond@stamus-networks.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
