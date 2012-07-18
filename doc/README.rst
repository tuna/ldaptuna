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


Shell Wrappers
--------------

Archlinux has Python 3 as ``python``, while more conservative distributions
have Python2 as ``python``. This makes it impossible to write a portable
shebang line (and you guessed it, I use Archlinux). To work around this, shell
wrappers ``ldaptuna`` and ``ldapvi`` were created.

FYI: Both ``ldapvi`` and ``ldaptuna`` are just symlinks to ``dopy``, which
looks at ``$0`` to decide which Python script to run.


Quickstart
----------

Run this to generate ~/.ldaptuna (in fact any valid command will do)::

 ./ldaptuna list domains

This will ask for a default user (just an identifier for the keyring item) and
the binddn (usually uid={name},ou=people,o=tuna) and bindpw (LDAP password)
to store in the keyring.

For xiaq, the conversation will look like::

 Defaut user: xiaq
 Bind DN: uid=xiaq,ou=people,o=tuna
 Password (^C to avoid saving password): [type type type]

Read help messages (some auto-generated doc, we need something better in
future)::

 ./ldaptuna -h
 ./ldaptuna list -h
 ./ldaptuna edit -h


Dependencies
------------

This software requires Python 2. I develop and test it with Python 2.7, but it
should run with Python 2.5 or 2.6. If it doesn't, it's a bug, and you may want
to tell me.

The following Python modules are required. They may be installed either
through your distribution's package manager or pypi (or easy_install if you
are really nostalgic).

* python-ldap

* argparse (preinstalled with Python 2.7)


License
-------

All files are licensed in the ISC license (2-clause BSD license, with fewer
words). See ``COPYING`` for a copy of the license.

