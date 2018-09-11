Hunt
====

.. _hunt:

Introduction
------------

Hunt is an interface dedicated to signatures and events visualization and tuning.
It is available from the top menu of Scirius Enterprise via the ``Hunt`` link.

Hunt uses a drill down approach to select events. Filters on protocol metadata
contained in the alerts events can be simply added by clicking on the magnifier
icons next to the field value.

Once a composite filter is defined the user can take an action based upon it. The
action will be applied to all future events matching the composite filter.

In the Community Edition, only the fields that can be used in suricata to create
suppression and threshold can be used. This is currently limited to ``src_ip`` and
``dest_ip``.

In Enterprise Edition, Stamus probes can have actions applied for filters
that use arbitrary protocol metadatas.

Pages
-----

Pages can be accessed via a click in the left menu. Jumping from one page to another
page will keep the filters untouched allowing the analyst to alternate between the
different views available.

Dashboard
~~~~~~~~~

This page displays a dashboard with statistics about the most interesting data and protocol metadata
that can be seen in alerts.

Signatures
~~~~~~~~~~

This page displays a list of signatures or signature page if a filter on a signature ID has been
created.

Alerts
~~~~~~

This page displays the individual alert events as a list. It is possible to expand an event to
see all details including metadata about it.

Actions
~~~~~~~

This page displays the list of actions. The list is ordered and the filter are applied in ascending order.

The actions can be reordered to adjust respective precedence of the filters. To do so simply click on the three dots on the right side of the action
and fill in the form 

History
~~~~~~~

This page displays the history of modifications done by the users on the Scirius instance.

Home
~~~~

Link to the Scirius homepage.

Actions
-------

Suppress
~~~~~~~~

A suppression action will delete matching events before they reach the storage.

In Scirius CE, a filter with a signature ID and a source or destination IP is needed to be able to create the action.

For Stamus probes, any fields can be used.

Threshold
~~~~~~~~~

A threshold action will only keep the alert when the defined threshold is reached.

In Scirius CE, a filter with a signature ID is needed to be able to create the action.

In Scirius EE and for Stamus probes, any fields can be used.

Tag
~~~

A `Tag` can be set based on a filter. It will be set on all matching events and will
permit an easy categorization.

Currently 2 values are available:

- Informational: information is just good enough to not be suppressed and is kept just in case
- Relevant: event is relevant and an investigation is needed

All events that are not tagged can be found under the `Untagged` label. If defined actions are
correctly set up it should be new signatures or unreferenced behavior. So investigation and classification
should be done.

Tag action is only available for Scirius EE and Stamus probes.

Tag and Keep
~~~~~~~~~~~~

A `Tag and keep` action is similar to the `Tag` action but a matching event
will not be suppressed or thesholded by any  of the actions found later
in the processing of actions.

Tag and keep action is only available for Scirius EE and Stamus probes.

Keyboard shortcuts
------------------

Tag filtering
~~~~~~~~~~~~~

Here is the complete list:

- `A`: display all events
- `R`: display only Relevant events
- `I`: display only Informational events
- `U`: display only Untagged events
