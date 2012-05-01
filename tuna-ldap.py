#!/usr/bin/python2
import os
import sys
import json
import base64
from getpass import getpass
from copy import deepcopy
from optparse import OptionParser

import ldapvi


conf_comment = '''User credentials are base64-encoded.
This is only meant to prevent occasional physical eavesdropping; it is *NOT* a
secure storage mechanism. Be sure to set strict permissions on this file (by
default permission bits 0600 is set but you may want to check to be sure), and
only store it on your personal computer.
'''.replace('\n', ' ')


def read_conf(fname):
    if os.path.exists(fname):
        conf = json.load(open(fname))
        conf0 = deepcopy(conf)
    else:
        os.close(os.open(fname, os.O_WRONLY | os.O_CREAT, 0600))
        conf0 = {}
        conf = {'default': '', 'secrets': {}, '_comment': conf_comment}
    return conf0, conf


def main():
    parser = OptionParser()
    parser.add_option('-u', '--user', '--as', type='string')

    opts, args = parser.parse_args(sys.argv[1:])

    # Determine what to do
    if len(args) < 2 or len(args) > 3:
        sys.exit(2)
    verb, part = args[0:2]
    name = len(args) == 3 and args[2] or ''
    base = 'ou=%s,o=tuna' % obj

    conf_name = os.path.join(os.environ['HOME'], '.tuna-ldap')
    conf0, conf = read_conf(conf_name)

    # Determine user
    user = opts.user or conf['default'] or raw_input('Default user: ')
    conf['default'] = conf['default'] or user

    # Determine binddn and bindpw
    secrets = conf['secrets']
    if secrets.has_key(user):
        binddn = secrets[user]['binddn']
        bindpw = secrets[user]['bindpw']
        if bindpw is not None:
            bindpw = base64.decodestring(bindpw)
    else:
        binddn = raw_input('Bind DN: ')
        try:
            bindpw = getpass('Password (^C to avoid saving password): ')
            bindpw = base64.encodestring(bindpw)
        except KeyboardInterrupt:
            bindpw = None
        secrets[user] = {
            'binddn': binddn,
            'bindpw': bindpw,
        }
    if conf != conf0:
        json.dump(conf, open(conf_name, 'w'), indent=2)
    if bindpw is None:
        bindpw = getpass('Password (one time): ')

    ldapvi.start('ldap://ldap.tuna.tsinghua.edu.cn', binddn, bindpw,
                 base=base)


if __name__ == '__main__':
    main()

