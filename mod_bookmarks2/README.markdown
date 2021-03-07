---
labels:
- 'Stage-Alpha'
summary: Synchronise bookmarks between Private XML and PEP
...

::: {.alert .alert-warning}
**WARNING:** This module is incompatible with clients which only use
[deprecated PEP bookmarks
(XEP-0048)](https://xmpp.org/extensions/xep-0048.html), such as
[Converse.js](https://conversejs.org).

If you need to be compatible with these clients, use
[mod\_bookmarks](mod_bookmarks.html) instead.
:::


Introduction
------------

This module fetches users’ bookmarks from Private XML and pushes them
to PEP on login, and then redirects any Private XML query to PEP.  This
allows interop between older clients that use [XEP-0048: Bookmarks
version 1.0](https://xmpp.org/extensions/attic/xep-0048-1.0.html) and
recent clients which use
[XEP-0402](https://xmpp.org/extensions/xep-0402.html).

Configuration
-------------

Simply [enable it like most other
modules](https://prosody.im/doc/installing_modules#prosody-modules), no
further configuration is needed.

Compatibility
-------------

  ------- ---------------
  trunk   Works
  0.11    Works
  0.10    Does not work
  0.9     Does not work
  ------- ---------------
