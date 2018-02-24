Updating Suricata ruleset
-------------------------

To update Suricata ruleset, you can go to ``Suricata -> Update`` (``Update`` being in the
``Actions`` menu). Then you have to select which action you want to do:

* Update: download latest version of the Sources used by the Ruleset
* Build: build a Suricata ruleset based on current version of the Sources
* Push: trigger a Suricata reload to have it running with latest build ruleset

You can also update the ruleset and trigger a Suricata reload by running ::

 python manage.py updatesuricata
