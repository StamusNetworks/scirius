Backup
======

To start a backup, run ::

 python manage.py scbackup

To restore a backup and erase all your data, you can run ::

 python manage.py screstore
 python manage.py migrate

This will restore the latest backup. To choose another backup, indicate a backup filename as first argument.
To get list of available backup, use ::

 python manage.py listbackups

You can not restore a backup to a scirius which is older than the one where the backup has been done.

With default configuration file, the backup is done on disk in `/var/backups` but other methods are available.
As Scirius CE is using django-dbbackup application for backup and restore procedures, it benefits from all available
methods in this application. This includes at least:

* FTP
* Amazon AWS
* Dropbox

Please see `django-dbbackup configuration <http://django-dbbackup.readthedocs.org/en/latest/storage.html>`_
for more information on available methods and on their configuration.
