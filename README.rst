ldaptuna
========

Introduction
------------

Two Python executables, ``ldapvi.py`` and ``ldaptuna.py`` live here.

``ldapvi.py`` is a more frugal implementation of the ``ldapvi`` tool; it's
generic, not TUNA-specific.

``ldaptuna.py`` is written with TUNA's LDAP tree structure in mind, and offers
a "keyring" mechanism to remember your password. The keyring is saved as a
JSON file in ``~/.ldaptuna``; you are encouraged to inspect and modify it by
hand.

Quickstart
----------

Run this to generate ~/.ldaptuna::

 ./ldaptuna.py list domains

This will ask for a default user, the binddn (usually
uid={name},ou=people,o=tuna) and bindpw (LDAP password). For xiaq, the dialog
will be::

 Defaut user: xiaq
 Bind DN: uid=xiaq,ou=people,o=tuna
 Password (^C to avoid saving password): [type type type]

Read help messages::
 ./ldaptuna.py -h
 ./ldaptuna.py list -h
 ./ldaptuna.py edit -h

Shebang
-------

Archlinux has Python 3 as ``python``, which is why I put ``python2`` in the
shebang line. If you use a more conservative distribution that has Python2 as
``python`` and ``python2`` is not available, you have to change the shebang
line yourself.

This has to be solved some day, but yet some day every distribution will have
Python 3 as ``python`` :)

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
