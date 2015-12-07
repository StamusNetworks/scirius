This directory contains Robotframework tests for Scirius.
Debian dependencies:
$ apt-get install vnc4server iceweasel wget python-virtualenv

Create a virtual environment:
$ virtualenv /path/to/env
$ source /path/to/env/bin/activate

Python dependencies:
$ pip install robotframework robotframework-selenium2library

Change the configuration:
$ vim config.txt

Run all the tests:
$ ./start.sh

Run specific tests (by tag):
$ ./start.sh -i source
$ ./start.sh -i ruleset
