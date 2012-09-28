import re
import os
import json
import base64
from os.path import dirname
from getpass import getpass
from copy import deepcopy
from argparse import ArgumentParser
from collections import namedtuple

import ldapvi


UnitSpec = namedtuple('UnitSpec', 'single plural key')


DEFAULT_CONF_NAME = '~/.ldaptuna'

CONF_COMMENT = '''WARNING: User credentials are base64-encoded.
This is only meant to prevent occasional physical eavesdropping; BY NO MEANS
IS IT A SECURE STORAGE MECHANISM. Be sure to set strict permissions on this
file (ldaptuna sets 0600 by default), and only store it on your personal
computer. If you accidentally stored the bindpw you can just change it to
null, which has the effect of asking you the password each time. (An empty
string means an empty password.)
'''.replace('\n', ' ')

BASEDN = 'o=tuna'

DEFAULT_BINDDN_FMT = 'uid={user},ou=people,' + BASEDN

URI_TEMPLATE = 'ldap://{server}.tuna.tsinghua.edu.cn'

SERVERS = ['ldap', 'ldap2']

UNITS = [
    UnitSpec('person', 'people', 'uid'),
    UnitSpec('robot', 'robots', 'cn'),
    UnitSpec('domain', 'domains', 'cn'),
    UnitSpec('host', 'hosts', 'cn'),
    UnitSpec('group', 'groups', 'cn'),
]

UNIT_MAP = {u.plural: u for u in UNITS}

UNIT_CNAME = {u.single: u.plural for u in UNITS}

UNIT_NAMES = UNIT_CNAME.keys() + UNIT_CNAME.values()


def get_conf_name():
    return re.sub('^~', os.environ['HOME'],
                  os.environ.get('LDAPTUNA', DEFAULT_CONF_NAME))


def read_conf(fname):
    if os.path.exists(fname):
        f = open(fname)
        conf = json.load(f)
        conf0 = deepcopy(conf)
    else:
        os.close(os.open(fname, os.O_WRONLY | os.O_CREAT, 0600))
        conf0 = {}
        conf = {'default': '', 'profiles': {}, '_comment': CONF_COMMENT}
    return conf0, conf


def get_bindinfo(user=''):
    conf_name = get_conf_name()
    conf0, conf = read_conf(conf_name)
    # Determine user
    user = user or conf['default'] or raw_input('''\
You didn't specify -p PROFILE on the command line, and there is no default profile found in your configuration. You need to provide the name of the default profile. When in doubt, use your LDAP username.

Default profile name: ''')
    conf['default'] = conf['default'] or user

    # Determine binddn and bindpw
    profiles = conf['profiles']
    if user in profiles:
        binddn = profiles[user]['binddn']
        bindpw = profiles[user]['bindpw']
        if bindpw is not None:
            bindpw = base64.decodestring(bindpw)
    else:
        print('Creating profile {user}'.format(user=user))
        default_binddn = DEFAULT_BINDDN_FMT.format(user=user)
        binddn = raw_input('Bind DN (defaulting to {dn}): '.format(
            dn=default_binddn)) or default_binddn
        try:
            bindpw = getpass('Password (Press ^C to avoid saving password.'
                             ' Do this when working on a public machine): ')
        except KeyboardInterrupt:
            print
            bindpw = None

        if bindpw is not None:
            raw_input('Be sure to read the comment in {conf}. '
                      'Press Enter now...'.format(conf=conf_name))

        profiles[user] = {
            'binddn': binddn,
            'bindpw': bindpw and base64.encodestring(bindpw),
        }
    if conf != conf0:
        json.dump(conf, open(conf_name, 'w'), indent=2)
    if bindpw is None:
        bindpw = getpass('Password (one time): ')
    return binddn, bindpw


def map_to_dn(basedn, unit, entity):
    dn = 'ou=%s,%s' % (unit, basedn)
    if entity:
        attr = UNIT_MAP[unit].key
        dn = '%s=%s,%s' % (attr, entity, dn)
    return dn


def mk_argparser():
    '''
    Build and return the main ArgumentParser.
    '''
    parser = ArgumentParser(description="TUNA's LDAP tool", prog='ldaptuna')
    parser.add_argument('-p', '--profile',
                        help='profile stored in ~/%s' % get_conf_name())
    parser.add_argument('-H', '--server', metavar='server', default='ldap',
                        choices=SERVERS,
                        help='''
        which server to query, possible values are %(choices)s
                        ''')

    subparsers = parser.add_subparsers(
        dest='subcommand', title='subcommands', help='''
        say `%(prog)s <subcommand> -h` to see help for subcommand
        ''')

    # Parent parser for apply, edit, list and new - the porcelain commands,
    # operating on the level of units and entities
    advcmd = ArgumentParser(add_help=False)
    advcmd.add_argument('unit', choices=UNIT_NAMES, metavar='unit',
                        help='''
        which part of LDAP (organizational unit) to operate on. Possible
        values are %(choices)s. Plural/singular pairs like people/person and
        domains/domain are equivalent
                        ''')
    advcmd.add_argument('entity', nargs='?', default='',
                        help='''
        which entity in selected unit to operate on. When omitted, operate on
        all entities within the selected unit.
                        ''')

    # Parent parser for commands that perform LDAP search (apply, edit and
    # list)
    searcher = ArgumentParser(add_help=False, parents=[advcmd])
    searcher.add_argument('-r', '-R', '--recursive', action='store_true',
                          default=False, help='list/modify subelements too')

    # A dummy ArgumentParser to define the file argument of apply command.
    # This is needed since there is no "insert_argument"...
    _apply_file = ArgumentParser(add_help=False)
    _apply_file.add_argument('file',
                             help='''
        LDIF file to apply against the search results
                             ''')

    def new_subcommand(name, **kwargs):
        return subparsers.add_parser(name, **kwargs)

    new_subcommand('apply', parents=[_apply_file, searcher])
    new_subcommand('edit', parents=[searcher], description='''
        fire an external editor to edit designated entity
        ''')
    new_subcommand('list', parents=[searcher], description='''
        output designated entity to stdout
        ''')
    new = new_subcommand('new', parents=[advcmd], description='''
              create designated entity from a template
              ''')
    new.add_argument('-t', '--template', default='', help='''
        If non-empty, use a template named <unit>.<template>.ldif instead of
        the default <unit>.ldif. The template is still looked for in the
        same template directory.
        ''')

    # search - the plumbing command (the only one for now)
    search = new_subcommand('search', description='''
        low-level LDAP search command
        ''')
    search.add_argument('-s', '--scope', default='sub',
                        choices=ldapvi.SCOPES.keys())
    search.add_argument('base')
    search.add_argument('filterstr', nargs='?', default='')

    return parser


def main():
    parser = mk_argparser()
    args = parser.parse_args()

    uri = URI_TEMPLATE.format(server=args.server)
    ldif = filterstr = ''
    # Determine what to do
    subcommand = args.subcommand
    if subcommand in ('apply', 'edit', 'list', 'new'):
        action = subcommand
        unit = args.unit
        # Canonize unit name
        if unit in UNIT_CNAME.keys():
            unit = UNIT_CNAME[unit]
        base = map_to_dn(BASEDN, unit, args.entity)

        if 'recursive' in args and args.recursive:
            scope = 'sub'
        else:
            scope = args.entity and 'base' or 'one'

        if subcommand == 'new':
            if args.template:
                name = '%s.%s.ldif' % (unit, args.template)
            else:
                name = '%s.ldif' % unit
            fname = os.path.join(dirname(dirname(__file__)), 'templates', name)
            if os.path.exists(fname):
                ldif = open(fname).read().format(name=args.entity or '{name}')
            else:
                ldif = '# Template %s not found, create from scratch' % fname
        elif subcommand == 'apply':
            ldif = open(args.file).read()
    elif subcommand == 'search':
        action = 'list'
        base, scope, filterstr = args.base, args.scope, args.filterstr

    binddn, bindpw = get_bindinfo(args.profile)

    ldapvi.start(uri, binddn, bindpw,
                 base=base, scope=scope, filterstr=filterstr,
                 action=action, ldif=ldif)


if __name__ == '__main__':
    main()
