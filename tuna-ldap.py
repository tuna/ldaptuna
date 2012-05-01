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


def parse_args(args):
    if len(args) < 2 or len(args) > 3:
        sys.exit(2)

    action = args[0]
    if action in ('edit', 'list', 'new', 'search'):
        pass
    elif action == 'ls':
        action = show
    else:
        print('Unknown action: %s' % action)
        sys.exit(2)

    unit = args[1]
    if unit in ('people', 'robots', 'domains', 'hosts'):
        pass
    else:
        print('Unknown unit: %s' % unit)
        sys.exit(2)

    base = 'ou=%s,o=tuna' % unit
    if len(args) == 3:
        name = args[2]
        if unit == 'people':
            attr = 'uid'
        else:
            attr = 'cn'
        base = '%s=%s,%s' % (attr, name, base)
    else:
        name = ''

    filterstr = ''

    ldif = ''
    if action == 'new':
        template = os.path.join(os.path.dirname(__file__), '%s.ldif' % unit)
        if os.path.exists(template):
            ldif = open(template).read().format(name=name or '{name}')
        else:
            ldif = '# Template %s not found, create from scratch' % template
    return base, filterstr, action, ldif


def main():
    usage = 'usage: %prog [options] <action> <unit> [name]'
    epilog = '''Action: one of edit, list, new, search'''
    parser = OptionParser(usage=usage, epilog=epilog)
    parser.add_option('-u', '--user', '--as', type='string',
                      help='the short username stored in ~/.ldap-tuna')
    parser.add_option('-r', '-R', '--recursive', action='store_true',
                      help='list/modify subentries too')

    opts, args = parser.parse_args(sys.argv[1:])

    # Determine what to do
    base, filterstr, action, ldif = parse_args(args)

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

    scope = opts.recursive and 'sub' or 'base'
    ldapvi.start('ldap://ldap.tuna.tsinghua.edu.cn', binddn, bindpw,
                 base=base, scope=scope, filterstr=filterstr,
                 action=action, ldif=ldif)


if __name__ == '__main__':
    main()

