#!/usr/bin/python2
import os
import sys
import json
import base64
from getpass import getpass
from copy import deepcopy
from argparse import ArgumentParser

import ldapvi


CONF_FNAME = '.ldaptuna'

CONF_COMMENT = '''User credentials are base64-encoded.
This is only meant to prevent occasional physical eavesdropping; it is *NOT* a
secure storage mechanism. Be sure to set strict permissions on this file (by
default permission bits 0600 is set but you may want to check to be sure), and
only store it on your personal computer.
'''.replace('\n', ' ')

BASEDN = 'o=tuna'

URI_TEMPLATE = 'ldap://{server}.tuna.tsinghua.edu.cn'


def read_conf(fname):
    if os.path.exists(fname):
        f = open(fname)
        conf = json.load(f)
        conf0 = deepcopy(conf)
    else:
        os.close(os.open(fname, os.O_WRONLY | os.O_CREAT, 0600))
        conf0 = {}
        conf = {'default': '', 'secrets': {}, '_comment': CONF_COMMENT}
    return conf0, conf


def get_bindinfo(user=''):
    conf_name = os.path.join(os.environ['HOME'], CONF_FNAME)
    conf0, conf = read_conf(conf_name)
    # Determine user
    user = user or conf['default'] or raw_input('Default user: ')
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
        except KeyboardInterrupt:
            bindpw = None
        secrets[user] = {
            'binddn': binddn,
            'bindpw': bindpw and base64.encodestring(bindpw),
        }
    if conf != conf0:
        json.dump(conf, open(conf_name, 'w'), indent=2)
    if bindpw is None:
        bindpw = getpass('Password (one time): ')
    return binddn, bindpw


def mk_argparser():
    parser = ArgumentParser(description='TUNA\'s LDAP tool')
    parser.add_argument('-u', '--user', '--as',
                        help='the short username stored in ~/%s' % CONF_FNAME)
    parser.add_argument('-H', '--server', default='ldap',
                        choices=['ldap', 'ldap2'],
                        help='Which server to query')

    # Parent parser for edit, list and new
    advcmd = ArgumentParser(add_help=False)
    units = ['people', 'robots', 'domains', 'hosts', 'groups']
    advcmd.add_argument('unit', choices=units)
    advcmd.add_argument('entity', nargs='?', default='')
    advcmd.add_argument('-r', '-R', '--recursive', action='store_true',
                        help='list/modify subentries too', default=False)

    subparsers = parser.add_subparsers(title='subcommands')
    for cmd in 'edit', 'list', 'new':
        subparser = subparsers.add_parser(cmd, parents=[advcmd])
        subparser.set_defaults(action=cmd)

    searchcmd = subparsers.add_parser('search')
    searchcmd.add_argument('-s', '--scope', default='sub',
                           choices=ldapvi.scopes.keys())
    searchcmd.add_argument('base')
    searchcmd.add_argument('filterstr', nargs='?', default='')
    searchcmd.set_defaults(action='search')

    #applycmd = subparsers.add_parser('apply')
    #applycmd.add_argument('file')
    #applycmd.set_defaults(action='apply')

    return parser


def main():
    parser = mk_argparser()
    args = parser.parse_args()

    uri = URI_TEMPLATE.format(server=args.server)
    ldif = filterstr = ''
    # Determine what to do
    if args.action in ('edit', 'list', 'new'):
        action = args.action
        base = 'ou=%s,%s' % (args.unit, BASEDN)
        if args.entity:
            if args.unit == 'people':
                attr = 'uid'
            else:
                attr = 'cn'
            base = '%s=%s,%s' % (attr, args.entity, base)
        scope = args.recursive and 'sub' or (args.entity and 'base' or 'one')

        if args.action == 'new':
            fname = os.path.join(os.path.dirname(__file__),
                                 'templates', '%s.ldif' % args.unit)
            if os.path.exists(fname):
                ldif = open(fname).read().format(name=args.entity or '{name}')
            else:
                ldif = '# Template %s not found, create from scratch' % fname
    elif args.action == 'search':
        action = 'list'
        base, scope, filterstr = args.base, args.scope, args.filterstr
    #elif args.action == 'apply':
    #    ldif = open(args.file).read()

    binddn, bindpw = get_bindinfo(args.user)

    ldapvi.start(uri, binddn, bindpw,
                 base=base, scope=scope, filterstr=filterstr,
                 action=action, ldif=ldif)


if __name__ == '__main__':
    main()

