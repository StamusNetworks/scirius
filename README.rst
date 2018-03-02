=======
Scirius
=======

Introduction
============

Scirius Community Edition is a web interface dedicated to Suricata ruleset management.
It handles the rules file and update associated files.

.. image:: https://github.com/StamusNetworks/scirius/raw/master/doc/images/suricata-index.png
    :alt: Suricata page
    :align: center

Scirius CE is developed by `Stamus Networks <https://www.stamus-networks.com/>`_ and is available under the
GNU GPLv3 license.

Features
========

Scirius can build Suricata ruleset composed of different sources. Sources or feeds can be public or custom.

.. image:: https://github.com/StamusNetworks/scirius/raw/master/doc/images/public-sources.png
    :alt: public sources from OISF
    :align: center

Scirius will take care of refreshing the sources and composing the ruleset by applying your transformation
on it.

.. image:: https://github.com/StamusNetworks/scirius/raw/master/doc/images/ruleset.png
    :alt: Ruleset with 5 sources
    :align: center

Transformations like disabling a rule or applying a threshold (to lower the noise only) can be made
for each rule or at the category level.

.. image:: https://github.com/StamusNetworks/scirius/raw/master/doc/images/rule-page.png
    :alt: Rule page
    :align: center

Scirius also presents statistics on rules activity to give information and facilitate the tuning.

Get Help
========

Documentation
-------------

`Scirius Documentation <https://scirius.readthedocs.io/en/latest/>`_ is on readthedocs.

Support
-------

You can join IRC #SELKS channel on `irc.freenode.net <http://freenode.net/>`_ to get help.

You can also ask Scirius related questions on `SELKS Forum <https://groups.google.com/forum/#!forum/selks>`_.

Report an issue
---------------

You can report an issue on `GitHub issue page <https://github.com/StamusNetworks/scirius/issues>`_.

Contributing
============

From improving the documentation to coding new features, there is more than one way to contribute to Scirius. And for
all contributions please use a `Pull Request <https://github.com/StamusNetworks/scirius/pulls>`_ on Github.
