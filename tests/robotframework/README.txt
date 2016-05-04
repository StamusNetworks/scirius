=== Installation ===
This directory contains Robotframework tests for Scirius.
Debian dependencies:
$ apt-get install vnc4server iceweasel wget python-virtualenv python-dev

Create a virtual environment:
$ virtualenv /path/to/env
$ source /path/to/env/bin/activate

Python dependencies:
$ pip install robotframework robotframework-selenium2library

=== Configuration ===
Change the configuration file to set the location of the manager (MANAGER_IP and BASE_URL) and a probe (DEFAULT_APPLIANCE_* variables):
$ vim config.txt

==== Running under Chrome configuration ====
To run the tests under chromium (WARNING: a "killall -9 chromium" is triggered using this method)
$ apt-get install chromium chromedriver

Edit the start.sh file and uncomment the BROWSER=chromium variable.

=== Running ===
Run all the tests:
$ ./start.sh 10_rules/ 20_appliances/

These tests expect to reach a Scirius manager at ${MANAGER_IP} and and Stamus probe at ${DEFAULT_APPLIANCE_IP}.
It will create a few objects, make tests and destroy them. Then, it will create reports in the current directory
as static web pagesin the current directory: report.html and log.html

Run specific actions:
To run specific actions without having to create/destroy objects everytime, you can use the separate scripts in
the tools/ directroy:

- Create a full setup:
$ ./start.sh -i create tools/

- Remove all source/ruleset/appliances
$ ./start.sh -i clean tools/

Check the .robot files in tools/ to see what Tags are defined to pass to the -i flag.

=== Contributions ===
How to contribute:
Since all tests/keywords are stored in tables, changing a single line
can trigger the modification of a lot of lines due to the reindentation. To mitigate this,
please separate all tests with a blank line: this way only the modified keyword will
need to be reindented.

You can use the rf_indent.py script in the tools/ directory to reindent the file correctly:
To reindent a file:
$ ./tools/rf_indent.py path/to/file.robot

To reindent everything:
$ ./tools/rf_indent.py config.txt $(find -name \*.robot)
