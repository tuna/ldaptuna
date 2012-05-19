ldaptuna
========

Introduction
------------

Two Python programs, ``ldapvi.py`` and ``ldaptuna.py`` live here.

``ldapvi.py`` is a more frugal implementation of the ``ldapvi`` tool; it's
generic, not TUNA-specific.

``ldaptuna.py`` is written with TUNA's LDAP tree structure in mind, and offers
a "keyring" mechanism to remember your password. The keyring is saved as a
JSON file in ``~/.ldaptuna``; you are encouraged to inspect and modify it by
hand.


Quickstart
----------

Run this to generate ~/.ldaptuna (in fact any valid command will do)::

 ./ldaptuna.py list domains

This will ask for a default user (just an identifier for the keyring item) and
the binddn (usually uid={name},ou=people,o=tuna) and bindpw (LDAP password)
to store in the keyring.

For xiaq, the conversation will look like::

 Defaut user: xiaq
 Bind DN: uid=xiaq,ou=people,o=tuna
 Password (^C to avoid saving password): [type type type]

Read help messages (some auto-generated doc, we need something better in
future)::

 ./ldaptuna.py -h
 ./ldaptuna.py list -h
 ./ldaptuna.py edit -h


Shell Wrapper
-------------

Archlinux has Python 3 as ``python``, while on more conservative distributions
have Python2 as ``python``.

I created a shell wrapper for Python scripts, ``runpy`` to work around this.
Both ``ldapvi`` and ``ldaptuna`` are symlinks to ``runpy``.

``runpy`` looks at ``$0`` to decide the corresponding Python source to run.


Dependencies
------------

* Python 2 (only tested with Python 2.7)

* python-ldap
  
* argparse (preinstalled with Python 2.7)


License
-------

All files are licensed in the ISC license (2-clause BSD license, with fewer
words), partly because GPL will make the source significantly larger. See
``COPYING`` for a copy of the license.

