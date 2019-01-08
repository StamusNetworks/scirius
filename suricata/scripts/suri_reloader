#!/usr/bin/python
"""
Copyright(C) 2014, Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import unicode_literals
import pyinotify
import argparse
import subprocess
import logging
import os

have_daemon = True
try:
    import daemon
    import daemon.pidfile as pidlockfile
except:
    logging.warning("No daemon support available, install python-daemon if feature is needed")
    have_daemon = False

RELOAD_FILE = "scirius.reload"

parser = argparse.ArgumentParser(description='Suricata reloader')
parser.add_argument('-r', '--reload', default=False, action="store_true", help="If set reload Suricata instead of restarting")
parser.add_argument('-p', '--path', default='/etc/suricata/rules', help='Directory to monitor for scirius.reload file')
parser.add_argument('-l', '--log', default=None, help='File to log output to (default to stdout)')
parser.add_argument('-v', '--verbose', default=False, action="count", help="Show verbose output, use multiple times increase verbosity")
if have_daemon:
    parser.add_argument('-D', '--daemon', default=False, action="store_true", help="Run as unix daemon")
    parser.add_argument('-P', '--pidfile', default='/var/run/suri-reloader.pid', help='PID file for suri-reloader')

args = parser.parse_args()

if args.verbose >= 3:
    loglevel=logging.DEBUG
elif args.verbose >= 2:
    loglevel=logging.INFO
elif args.verbose >= 1:
    loglevel=logging.WARNING
else:
    loglevel=logging.ERROR

def SuriReload(reload = False):
    if reload:
        if subprocess.call(['service', 'suricata', 'reload']):
            logging.error("Unable to reload suricata")
        else:
            logging.info("Reloaded suricata")
    else:
        if subprocess.call(['service', 'suricata', 'restart']):
            logging.error("Unable to restart suricata")
        else:
            logging.info("Restarted suricata")

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CLOSE_WRITE(self, event):
        if not RELOAD_FILE in event.pathname:
            return
        SuriReload(self.reload)
        os.unlink(event.pathname)

    def set_mode(self, mode):
        if mode == "reload":
            self.reload = True
        else:
            self.reload = False

def setup_logging(args):
    if args.log:
        logging.basicConfig(filename=args.log,
                            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                            level=loglevel)
    else:
        logging.basicConfig(level=loglevel)

def main_task(args):
    setup_logging(args)

    reload_file = os.path.join(args.path, RELOAD_FILE)
    if os.path.isfile(reload_file):
        SuriReload(args.reload)
        os.unlink(reload_file)

    handler = EventHandler()
    if args.reload:
        handler.set_mode("reload")
    else:
        handler.set_mode("restart")

    wm = pyinotify.WatchManager()  # Watch Manager
    mask = pyinotify.IN_CLOSE_WRITE
    notifier = pyinotify.Notifier(wm, handler)
    wdd = wm.add_watch(args.path, mask, rec=True)
    logging.info("Starting filesystem monitoring")
    notifier.loop()

if have_daemon and args.daemon:
    pidfile = pidlockfile.TimeoutPIDLockFile(args.pidfile)
    with daemon.DaemonContext(pidfile=pidfile):
        main_task(args)
else:
    main_task(args)
