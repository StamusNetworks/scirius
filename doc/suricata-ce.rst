Suricata management
===================

Setup
-----

The Suricata edit page allows you to setup the parameters of the Suricata.

The parameters are the following:

* Name: hostname of the probe, be sure it is matching value of `host` field in JSON events
* Descr: description of the suricata
* Rules directory: `scirius.rules` file will be created in this directory. Suricata must only use this file
* Suricata configuration file: used to detect some configuration settings
* Ruleset: choose the ruleset to use

Updating ruleset
----------------

To update Suricata ruleset, you can go to ``Suricata -> Update`` (``Update`` being in the
``Actions`` menu). Then you have to select which action you want to do:

* Update: download latest version of the Sources used by the Ruleset
* Build: build a Suricata ruleset based on current version of the Sources
* Push: trigger a Suricata reload to have it running with latest build ruleset

You can also update the ruleset and trigger a Suricata reload by running ::

 python manage.py updatesuricata
