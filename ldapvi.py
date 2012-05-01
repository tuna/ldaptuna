#!/usr/bin/python2
import os
import sys
from subprocess import check_call, CalledProcessError
from optparse import OptionParser
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

retcodes = {
    '': 0,
    'cmdline': 2,
    'cancelled': 3,
    'connect': 4,
    'starttls': 5,
    'bind': 6,
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
    sys.exit(retcodes[why])


def fire_editor(fname):
    editor = os.environ.get('EDITOR', '')
    if editor:
        try:
            check_call([editor, fname])
        except CalledProcessError as e:
            print('Editor %s failed with return code %d, ' \
                  'fall back to manual mode' % ( editor, e.returncode))
    else:
        print('Now modify %s, and press Enter when you are done' % fname)
        print('(Hint: set environment variable $EDITOR ' \
              'to launch automatically)')
        raw_input()


def mkchanges(old, new):
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
    _dnli = {}
    for dn, attrs in entries:
        li = dn.split(',')
        li.reverse()
        _dnli[dn] = li
    entries.sort(lambda a, b: cmp(_dnli[a[0]], _dnli[b[0]]))
    return entries


def start(uri, binddn, bindpw, starttls=True,
          base='', scope='sub', filterstr='',
          verb='edit', ldif=''):
    def efmt(e):
        msg = e.args[0]
        s = msg['desc']
        if msg.has_key('info'):
            s += ' (%s)' % (msg['info'])
        return s

    def error(s, e):
        sys.stderr.write('Failed to %s:\n    %s\n' % (s, efmt(e)))

    try:
        conn = ldap.initialize(uri)
    except LDAPError as e:
        error('connect to %s' % uri, e)
        return 'connect'
    if starttls:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        try:
            conn.start_tls_s()
        except LDAPError as e:
            error('starttls', e)
            return 'starttls'
    try:
        conn.bind_s(binddn, bindpw)
    except ldap.LDAPError as e:
        error('login as %s' % binddn, e)
        return 'bind'

    # Open LDIF file for writing
    if verb in ('edit', 'new'):
        fd, fname = mkstemp('.ldif')
        fldif = os.fdopen(fd, 'w')

    if verb in ('list', 'edit'):
        # Search, sort and unparse
        old = sort_entries(conn.search_s(
            base, scopes[scope], filterstr or '(objectClass=*)'))

        if verb == 'list':
            fldif = sys.stdout
        writer = LDIFWriter(fldif)

        for dn, attrs in old:
            writer.unparse(dn, attrs)

    if verb in ('edit', 'new'):
        # Save old entries, prepair LDIF file and open for reading
        if verb == 'edit':
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

        while True:
            reply = raw_input(msg).lower()
            if reply == 'n':
                print('LDIF saved in %s' % fname)
                return 'cancelled'
            elif reply in ('', 'y'):
                break
            else:
                print('Invalid input, try again')

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

    parser = OptionParser()
    for t in stropts:
        parser.add_option(*t, type='string')
    for t in boolopts:
        parser.add_option(*t, action='store_true', default=False)
    parser.add_option('-s', '--scope',
                      type='choice', choices=scopes.keys(), default='sub')

    opts, args = parser.parse_args(sys.argv[1:])

    if len(args) == 0:
        filterstr = ''
    elif len(args) == 1:
        filterstr = args[0]
    else:
        print('Only one argument, the filter, is accepted')
        exit('cmdline')

    for opt in 'uri', 'binddn', 'base':
        if not getattr(opts, opt):
            setattr(opts, opt, raw_input('%s? ' % opt))

    if opts.askpw:
        opts.bindpw = getpass()

    exit(start(opts.uri, opts.binddn, opts.bindpw, opts.starttls,
               opts.base, opts.scope, filterstr))


if __name__ == '__main__':
    main()

