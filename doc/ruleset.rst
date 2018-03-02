Rulesets
========

Philosophy of Ruleset handling
------------------------------

Scirius allows you to define a ``Ruleset`` which is a set of rules defining the behaviour
of Stamus Networks Suricata  probes regarding detection and inspection. You can have as many 
Rulesets as you would like and you can attach a particular ``Ruleset`` to many ``Appliances``.

A Ruleset is made of components selected in different ``Sources``. A Source is a set of
files providing information to Suricata. For example, this can be EmergingThreats 
ruleset downloaded from the official ET URL (or any other URL) or uploaded locally.

User actions logging
--------------------

All actions done in ruleset management are logged. It is possible to access
their history by using `Actions history`_ in the Stamus icon menu.

Optional comment are available for each action to allow users to interact
with each other.

Ruleset management
------------------

The ruleset management encompasses both the ``Rulesets`` and ``Sources`` major menu options.

To create a ruleset, you thus must create a set of ``Sources`` and then link them to the
ruleset. Once this is done, you can select which elements of the source you want to
use. For example, in the case of a signature ruleset, you can select which categories
you want to use and which individual signature you want do disable.

Once a Ruleset is defined, you can attach it to a Appliance. To do that simply edit
the Appliance object and choose the Ruleset in the list.

Creating Source
---------------

There is two methods to create a Source. First one is to use predefined public sources
and the second one via manual addition.

Public sources
~~~~~~~~~~~~~~

Go to ``Sources -> Add public source`` (``Add`` being in the ``Actions`` menu in the sidebar).

Choose a source and click on the ``Add`` button. In the popup you can select to which ruleset you
want to add the source. In some cases there will be some fields like the secret key provided by
the rules editors to be entered.

Manual addition
~~~~~~~~~~~~~~~

To create a Source go to ``Sources -> Add custom source`` (``Add`` being in the
``Actions`` menu in the sidebar). Then set the different fields and click ``Submit``.

A source of datatype ``Signatures files in tar archive`` has to follow some rules:

* It must be a tar archive
* All files must be under a ``rules`` directory

For example, if you want to fetch ETOpen Ruleset for Suricata 4.0, you can use:

* Name: ETOpen Ruleset
* URI: https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz

A source of datatype ``Individual signature files`` has to be a single file containing
signatures.

For example, if you want to use SSL blacklist from abuse.ch, you can use:

* Name: SSLBL abuse.ch
* URI: https://sslbl.abuse.ch/blacklist/sslblacklist.rules

A source of datatype ``Other content`` has to be a single file. It will be copied
to Suricata rules directory using its name as filename.

Updating Source
---------------

To update a Source, you first need to select it. To do that, go to ``Sources`` then
select the wanted Source in the array.

You can then click on ``Update`` in the menu in the sidebar. This step can take long
as it can require some download and heavy parsing.

Once updated, you can browse the result by following links in the array.

Creating Ruleset
----------------

To create a Ruleset go to ``Ruleset -> Add`` (``Add`` being in the
``Actions`` menu in the sidebar). Then set the name of the Ruleset
and choose which Sources to use and click ``Submit``.

Updating Ruleset
----------------

To update a Ruleset, you first need to select it. To do that, go to ``Ruleset`` then
select the wanted Ruleset in the array.

You can then click on ``Update`` in the ``Action`` menu in the sidebar. This step can take long
as it can require download of different Sources and heavy parsing.

Editing Ruleset
---------------

To edit a Ruleset, you first need to select it. To do that, go to ``Ruleset`` then
select the wanted Ruleset in the array.

You can then click on ``Edit`` in the ``Action`` menu in the sidebar. 

There is now different operations available in the ``Action`` menu

* Edit sources: select which sources of signatures to use in the Ruleset
* Edit categories: select which categories of signatures to use in the Ruleset
* Add rule to suppressed list: if a rule is in this list then it will not be part of the generated Ruleset
* Remove rule from suppressed list: this remove a rule from the previously mentioned list thus re-enabling it in the Ruleset

Edit Sources
~~~~~~~~~~~~

To select which Sources to use, just select them via the checkbox and click on ``Update sources``. Please
note that selecting categories to enable is the next step in the process when you add a new source.

Edit Categories
~~~~~~~~~~~~~~~

To select which Categories to use, just select them via the checkbox and click on ``Update categories``.

Add rule to suppressed list
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the search field to find the rule(s) you want to remove, you can use the SID or any other element in the signature. Scirius will search the entered text in the definition of signature and return you the list of rules.
You will then be able to remove them by clicking on the check boxes and clicking on ``Add selected rules to suppressed list``.

Remove rule from suppressed list
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To remove rules from suppressed list, simply check them in the array and click on ``Remove select rules from suppressed list``.


Suppression and thresholding
----------------------------

Alert numbers from a particular SN probe for a particular signature can be controlled through suppression or thresholding.
Thresholding is usually used when number of alerts needs to be  minimized - as for example maximum 1 alert per minute from that source or destination IP for that signature.
Suppression is used when the alerts need to be suppressed - aka do not generate alerts for that particular signature from that source or destination IP.

Suppress alerts
~~~~~~~~~~~~~~~

Click on ``Appliances`` and select/choose the desired StamusN probe. Click on the particular ``sid`` for the alerts that would need to be suppressed. On the 
new screen make sure you are on the ``Rule stats`` tab then you can either click on ``Suppress rule`` under ``Action`` on the menu on the left hand side or choose directly by source or destination by clicking on 
the ``x`` next to the IP address. On the new page you will be informed if there already is some threshold or suppression in effect for that particular signature.
The available fields are: 

- ``Ruleset`` for which ruleset this configuration applies
- ``Track by`` (mandatory field) to track by source or destination IP
- ``Net`` for which IP and/or particular network is that valid.

Choose the ruleset , source or destination (for that particular IP) and click ``+Add``.

You can also choose to enforce the suppression for a whole network and/or use a list of IPs. You can add in the ``Net`` field like so:  ::

 10.10.10.0/24,1.1.1.1,2.2.2.2

You can verify the suppression by clicking on the ``Rules info`` tab. You will have an informational display about the status of the different (if any) threshold and suppression configurations.
Alternatively you can also view that by clicking ``Rulesets`` and selecting the ruleset for which you have applied the particular suppression or threshold.

In order for the suppression to become active you need to ``Push`` the updated ruleset to the probes. See `Updating Appliances ruleset`_ for complete instruction.


Threshold alerts
~~~~~~~~~~~~~~~~

Click on ``Appliances`` and select/choose the desired StamusN probe. Click on the particular ``sid`` for the alerts that would need to be thresholded. On the 
new screen make sure you are on the ``Rule stats`` tab then you can either click on ``Threshold`` under ``Action`` on the menu on the left hand side or choose directly by source or destination by clicking on 
the arrow down (next to ``x``) next to the IP address. On the new page you will be informed if there already is some threshold or suppression in effect for that particular signature.
The available fields are: 

- ``Type`` type of the threshold. It can be:
  
  ``limit`` - limits the alerts to at most "X" times.
  
  ``threshold`` - minimum threshold for a rule before it generates an alert.
  
  ``both`` - both limiting and thresholding are applied.
  
- ``Ruleset`` for which ruleset this configuration applies
- ``Track by`` (mandatory field) to track by source or destination IP
- ``Count`` number of times the alert is generated.
- ``Seconds`` within that timespan

You can verify the thresholding by clicking on the ``Rules info`` tab. You will have an informational display about the status of the different (if any) threshold and suppression configurations.
Alternatively you can also view that by clicking ``Rulesets`` and selecting the ruleset for which you have applied the particular suppression or threshold.

In order for the suppression to become active you need to ``Push`` the updated ruleset to the probes. See `Updating Appliances ruleset`_ for complete instruction.

Rule transformation
-------------------

Rule transformation allows the action of a particular rule to be changed - to drop, reject or filestore.
Please note these actions requires advanced knowledge about rules and the rule keywords language.

Once you have a particular rule that you would like to transform  - in the rule's details page on the left hand side panel under ``Actions`` click 
``Transform rule``. You will be presented with a few choices:  

- Type of transformation to choose form:  

  ``drop`` - (IPS mode) will convert the rule from alert to drop - aka IPS mode needs to be explicitly set up and configured before hand.
  
  ``reject`` - (IDPS/hybrid) will convert the rule from alert to reject meaning that when triggered a RST/or dst unreachable  packets will be send to both the src and dst IP.
  
  ``filestore`` - will convert those rules only that have protocols allowing for file extraction - for example ``alert http...`` or ``alert smtp``
  
- Choose a ruleset you wish the newly transformed rule to be added/registered in.

**NOTE:** A particular rule can be transformed only once.

**NOTE:** For using the ``drop`` functionality you need to have a valid IPS setup.

After you make the desired selection you can add in a comment for the purpose of accountability and click on ``Valid``.
You will have the details about the transformed rule in the ``Information`` tab. You can review and confirm the transformation and the ruleset it is add in alongside any comments.

Only rules that are active can be transformed. If a rule is not active in a particular ruleset it will not have the transformation or 
suppress/threshold options available on the left hand side panel. To make it active you can toggle the availability of that rule by clicking 
on the ``Toggle availability`` option on the left hand side panel menu.

The history tab of the rule details page will have any comments and changes to the transformed rule for traceability.


