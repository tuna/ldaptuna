import os
import sys
from subprocess import check_call, CalledProcessError
from argparse import ArgumentParser
from tempfile import mkstemp
from getpass import getpass
from pprint import pprint

import ldap
import ldap.modlist
import ldif
from ldap import LDAPError


scopes = {
    'base': ldap.SCOPE_BASE,
    'one': ldap.SCOPE_ONELEVEL,
    'sub': ldap.SCOPE_SUBTREE
}

_retcodes = {
    '': 0,
    'cmdline': 2,
    'cancelled': 3,
    'connect': 4,
    'operation': 7,
}

class LDIFParser(ldif.LDIFParser):
    def __init__(self, *args, **kwargs):
        ldif.LDIFParser.__init__(self, *args, **kwargs)
        self._entries = {}

    def handle(self, dn, entry):
        self._entries[dn] = entry

    def parse(self):
        ldif.LDIFParser.parse(self)
        return self._entries


class LDIFWriter(ldif.LDIFWriter):
    force_plain = set(['description', 'l', 'tunaZhName', 'tunaLdapLogin'])
    def _needs_base64_encoding(self, type_, value):
        return type_ not in self.force_plain and \
               ldif.LDIFWriter._needs_base64_encoding(self, type_, value)


def exit(why):
    sys.exit(_retcodes[why])


def fire_editor(fname):
    editor = os.environ.get('EDITOR', '')
    if editor:
        try:
            check_call([editor, fname])
            return
        except CalledProcessError as e:
            print('Editor %s failed with return code %d, ' \
                  'falling back to manual mode' % ( editor, e.returncode))
    print('Now modify %s, and press Enter when you are done' % fname)
    if not editor:
        print('(Hint: set environment variable $EDITOR ' \
              'to launch automatically)')
    raw_input()


def mkchanges(old, new):
    '''Generate add, modify and delete modlists from two LDAP entry lists.'''
    changes = {
        'add': [],
        'modify': [],
        'delete': []
    }
    for dn in new.keys():
        if old.has_key(dn):
            if old[dn] == new[dn]:
                continue
            modlist = ldap.modlist.modifyModlist(old[dn], new[dn])
            changes['modify'].append((dn, modlist))
        else:
            modlist = ldap.modlist.addModlist(new[dn])
            changes['add'].append((dn, modlist))

    for dn in old.keys():
        if not new.has_key(dn):
            changes['delete'].append((dn,))
    return changes


def sort_entries(entries):
    '''Sort LDAP entries by DN.'''
    _dnli = {}
    for dn, attrs in entries:
        li = dn.split(',')
        li.reverse()
        _dnli[dn] = li
    entries.sort(lambda a, b: cmp(_dnli[a[0]], _dnli[b[0]]))
    return entries


def connect(uri, binddn, bindpw, starttls=True):
    conn = ldap.initialize(uri)
    if starttls:
        # XXX
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        conn.start_tls_s()
    conn.bind_s(binddn, bindpw)
    return conn


def ask(prompt, choices, default=None):
    while True:
        reply = raw_input(prompt).lower()
        if reply in choices:
            return reply
        if reply == '' and default is not None:
            return default
        print('Invalid input, try again')


def start(uri, binddn, bindpw, starttls=True,
          base='', scope='sub', filterstr='',
          action='edit', ldif=''):
    def efmt(e):
        msg = e.args[0]
        s = msg['desc']
        if msg.has_key('info'):
            s += ' (%s)' % (msg['info'])
        return s

    def error(s, e):
        sys.stderr.write('Failed to %s:\n    %s\n' % (s, efmt(e)))

    try:
        conn = connect(uri, binddn, bindpw, starttls)
    except LDAPError as e:
        error('connect to %s as %s %s' % (
              uri, binddn, starttls * 'with TLS'), e)
        return 'connect'

    # Open LDIF file for writing
    if action in ('edit', 'new'):
        fd, fname = mkstemp('.ldif')
        fldif = os.fdopen(fd, 'w')

    # Write LDIF
    if action in ('list', 'edit'):
        # Search, sort and unparse
        old = sort_entries(conn.search_s(
            base, scopes[scope], filterstr or '(objectClass=*)'))

        if action == 'list':
            fldif = sys.stdout
        writer = LDIFWriter(fldif)

        for dn, attrs in old:
            writer.unparse(dn, attrs)

    # Read and apply LDIF
    if action in ('edit', 'new'):
        # Save old entries, prepair LDIF file and open for reading
        if action == 'edit':
            old = dict(old)
        else:
            old = {}
            fldif.write(ldif)
        fldif.close()
        fire_editor(fname)
        fldif = open(fname)

        parser = LDIFParser(fldif)
        new = parser.parse()
        changes = mkchanges(old, new)

        msg = 'add %d, modify %d, delete %d. Confirm? [Y/n] ' % (
              len(changes['add']), len(changes['modify']),
              len(changes['delete']))

        reply = ask(msg, 'yn', 'y')
        if reply == 'n':
            print('LDIF saved in %s' % fname)
            return 'cancelled'

        allgood = True
        for op in 'add', 'modify', 'delete':
            func = getattr(conn, '%s_s' % op)
            for change in changes[op]:
                try:
                    func(*change)
                except ldap.LDAPError as e:
                    error('%s %s' % (op, change[0]), e)
                    allgood = False

        if allgood:
            os.unlink(fname)
            print('Done.')
            return ''
        else:
            print('LDIF saved in %s' % fname)
            return 'operation'


def main():
    stropts = [
        ('-H', '--uri'),
        ('-D', '--binddn', '--user'),
        ('-w', '--bindpw', '--password'),
        ('-b', '--base'),
    ]
    boolopts = [
        ('-Z', '--starttls'),
        ('-i', '--interactive'),
        ('-W', '--askpw'),
    ]

    parser = ArgumentParser(description='A more frugal ldapvi in Python')
    for t in stropts:
        parser.add_argument(*t, type=str)
    for t in boolopts:
        parser.add_argument(*t, action='store_true', default=False)
    parser.add_argument('-s', '--scope', type=str,
                        choices=scopes.keys(), default='sub')
    parser.add_argument('filterstr', nargs='?', default='')

    args = parser.parse_args()

    for opt in 'uri', 'binddn', 'base':
        if not getattr(args, opt):
            setattr(args, opt, raw_input('%s? ' % opt))

    if args.askpw:
        args.bindpw = getpass()

    exit(start(args.uri, args.binddn, args.bindpw, args.starttls,
               args.base, args.scope, args.filterstr))


if __name__ == '__main__':
    main()

