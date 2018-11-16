.. _rulesets:

Rulesets
========

Philosophy of Ruleset handling
------------------------------

Scirius allows you to define a ``Ruleset`` which is a set of rules defining the behaviour
of Stamus Networks Suricata  probes regarding detection and inspection. You can have as many 
Rulesets as you would like and you can attach a particular ``Ruleset`` to many ``Appliances``.

.. index:: Ruleset

A Ruleset is made of components selected in different ``Sources``. Transformation such
as removing some rules, altering content can be applied to the signatures in the
ruleset before it is pushed to the network probe(s).

.. index:: Source

A Source is a set of
files providing information to Suricata. For example, this can be EmergingThreats 
ruleset downloaded from the official ET URL (or any other URL) or uploaded locally.

.. index:: Category

When a Source containing Signatures is splitted in multiple files, the set of Signatures in each individual
file is called a Category.

User actions logging
--------------------

All actions done in ruleset management are logged. It is possible to access
their history by using ``Actions history`` in the Stamus icon menu.

Optional comment are available for each action to allow users to interact
with each other.

Ruleset management
------------------

The ruleset management encompasses both the ``Rulesets`` and ``Sources`` major menu options.

To create a ruleset, you thus must create a set of ``Sources`` and then link them to the
ruleset. Once this is done, you can select which elements of the source you want to
use. For example, in the case of a signature ruleset, you can select which categories
you want to use and which individual signature you want do disable.

Once a Ruleset is defined, you can attach it to a Probe. To do that simply edit
the Probe object and choose the Ruleset in the list.

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

If method is ``HTTP URL``, you will see an ``Optional authorization key`` field. This
field is optional and can be used to authenticate Scirius against the remote server.
It adds an authorization header to HTTP request allowing authentication on a large number of
third party services.
This can be used in particular to import signatures from a `MISP <http://www.misp-project.org/>`_ instance. See
`MISP documentation <https://www.circl.lu/doc/misp/automation/#automation-api>`_ for more information.

The usage of private Github repositories to host signatures is also supported through the usage of ``Optional auhtorization key``, as explained in the `Github documentation <https://developer.github.com/v3/auth/>`_. ``Optional auhtorization key`` should be filled with ``token TOKEN``, with the second TOKEN being the personal access token created under the user Github profile, Developer Settings page.

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

You can select the Sources to use and the transformations to apply. For more informations
about them, see :ref:`rule-transformations`.

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

Alert numbers for a particular signature can be controlled through suppression or thresholding.

.. index:: Thresholding

Thresholding is usually used when number of alerts needs to be  minimized - as for example maximum 1 alert per minute from that source or destination IP for that signature.

.. index:: Suppression

Suppression is used when the alerts need to be suppressed - aka do not generate alerts for that particular signature from that source or destination IP.

Suppress alerts
~~~~~~~~~~~~~~~

From any table displaying a list of alerts, click on the particular ``sid`` for the alerts that would need to be suppressed. This will
display the rule page. There you can click on ``Edit rule`` under ``Action`` on the menu on the left hand side, then select ``Suppress rule`` in the same menu.
From the rule page you can also reach the suppression creation page by being on the ``Ip and Time stats`` or ``Advanced Data`` tabs and clicking on 
the ``x`` next to the IP address.

On the new page you will be informed if there already is some threshold or suppression in effect for that particular signature.
The available fields are: 

- ``Ruleset`` for which ruleset this configuration applies
- ``Track by`` (mandatory field) to track by source or destination IP
- ``Net`` for which IP and/or particular network is that valid.

Choose the ruleset , source or destination (for that particular IP) and click ``+Add``.

You can also choose to enforce the suppression for a whole network and/or use a list of IPs. You can add in the ``Net`` field like so:  ::

 10.10.10.0/24,1.1.1.1,2.2.2.2

You can verify the suppression by clicking on the ``Rules info`` tab. You will have an informational display about the status of the different (if any) threshold and suppression configurations.
Alternatively you can also view that by clicking ``Rulesets`` and selecting the ruleset for which you have applied the particular suppression or threshold.

In order for the suppression to become active you need to ``Push`` the updated ruleset to the probes. See :ref:`updating-appliances-ruleset` on SEE and :ref:`updating-suricata` on Scirius CE for complete instruction.


Threshold alerts
~~~~~~~~~~~~~~~~

From any table displaying a list of alerts, click on the particular ``sid`` for the alerts that would need to be suppressed. This will
display the rule page. There you can click on ``Edit rule`` under ``Action`` on the menu on the left hand side, then select ``Threshold rule`` in the same menu.
From the rule page you can also reach the threshold creation page by being on the ``Ip and Time stats`` or ``Advanced Data`` tabs and clicking on 
the arrow down (next to the ``x``) next to the IP address.

On the new page you will be informed if there already is some threshold or suppression in effect for that particular signature.
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

In order for the threshold to become active you need to ``Push`` the updated ruleset to the probes. See :ref:`updating-appliances-ruleset` on SEE and :ref:`updating-suricata` on Scirius CE for complete instruction.

.. _rule-transformations:

Rule transformations
--------------------

.. index:: Transformations

There is three types of rules transformations.  
The first one `Action` allows the action of a particular rule to be changed - to drop, reject or filestore.
Please note these actions requires advanced knowledge about rules and the rule keywords language.
Second one is `Lateral` that modify the rules to detect lateral movement and third one is `Target` that update
signatures by adding the target keyword.

Transformation are relative to a ruleset. But they can be set globally on a ruleset or set on a category or on a specific rule. So it is easy to handle exceptions.

Action transformation
~~~~~~~~~~~~~~~~~~~~~

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

Lateral movement
~~~~~~~~~~~~~~~~

Signatures are often written with the EXTERNAL_NET and HOME_NET variables and this means they won't match
if both sides of a flow are in the HOME_NET. Thus, lateral movements are not detected. This transformation
change EXTERNAL_NET to any to be able to detect lateral movements.

The option can have three values:

- No: the replacement is not done
- Yes: EXTERNAL_NET is replaced by any
- Auto: Substitution is done if signature verify some properties

Target keyword
~~~~~~~~~~~~~~

Available since Suricata 4.0, the target keyword can be used to tell which side of a flow triggering
a signature is the target. If this key is present then related events are enhanced to contain the source
and target of the attack.

The option can have four values:

- Auto: an algorithm is used to determine the target if there is one
- Destination: target is the destination IP
- Source: target is the source IP
- None: no transformation is done

