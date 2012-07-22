import os
import sys
from subprocess import check_call, CalledProcessError
from argparse import ArgumentParser
from collections import OrderedDict
from tempfile import mkstemp
from getpass import getpass

import ldap
import ldap.modlist
import ldif
from ldap import LDAPError


SCOPES = {
    'base': ldap.SCOPE_BASE,
    'one': ldap.SCOPE_ONELEVEL,
    'sub': ldap.SCOPE_SUBTREE
}

_RETCODES = {
    '': 0,
    'cmdline': 2,
    'cancelled': 3,
    'connect': 4,
    'operation': 7,
}


class LDIFParser(ldif.LDIFParser):
    def handle(self, dn, entry):
        self._entries[dn] = entry

    def parse(self):
        self._entries = OrderedDict()
        ldif.LDIFParser.parse(self)
        return self._entries


class LDIFWriter(ldif.LDIFWriter):
    pass
    # XXX Suppressing base64 sometimes breaks the encoding.
    # This might be a bug of ldif module.
#    force_plain = set(['description', 'l', 'tunaZhName', 'tunaLdapLogin'])
#    def _needs_base64_encoding(self, type_, value):
#        return type_ not in self.force_plain and \
#               ldif.LDIFWriter._needs_base64_encoding(self, type_, value)


def exit(why):
    sys.exit(_RETCODES[why])


def fire_editor(fname):
    '''
    Fire an external editor to edit file named fname.
    '''
    editor = os.environ.get('EDITOR', '')
    if editor:
        try:
            check_call([editor, fname])
            return
        except CalledProcessError as e:
            print('Editor %s failed with return code %d, '
                  'falling back to manual mode' % (editor, e.returncode))
    print('Now modify %s, and press Enter when you are done' % fname)
    if not editor:
        print('(Hint: set environment variable $EDITOR to'
              ' launch automatically)')
    raw_input()


def mkchanges(old, new):
    '''
    Generate add, modify and delete modlists by diffing two LDAP entry lists.

    Return a dict keyed 'add', 'modify' and 'delete'. The values are lists of
    tuples - (dn, modlist) for 'add' and 'modify', (dn,) for 'delete',
    suitable to be passed as arguments to conn.add_s, conn.modify_s and
    conn.delete_s respectively, where conn is an instance of
    ldap.ldapobject.LDAPObject.
    '''
    changes = {
        'add': [],
        'modify': [],
        'delete': []
    }
    for dn in new.keys():
        if dn in old:
            if old[dn] == new[dn]:
                continue
            modlist = ldap.modlist.modifyModlist(old[dn], new[dn])
            changes['modify'].append((dn, modlist))
        else:
            modlist = ldap.modlist.addModlist(new[dn])
            changes['add'].append((dn, modlist))

    for dn in old.keys():
        if dn not in new:
            changes['delete'].append((dn,))
    return changes


def sort_entries(entries):
    '''
    Sort LDAP entries by DN, ensuring parent elements appear before their
    children.
    '''
    _dnli = {}
    for dn, attrs in entries:
        li = dn.split(',')
        li.reverse()
        _dnli[dn] = li
    entries.sort(lambda a, b: cmp(_dnli[a[0]], _dnli[b[0]]))
    return entries


def connect(uri, binddn, bindpw, starttls=True):
    '''
    Perform a combo of LDAP initialization and binding and return the
    connection.
    '''
    conn = ldap.initialize(uri)
    if starttls:
        # XXX
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        conn.start_tls_s()
    conn.bind_s(binddn, bindpw)
    return conn


def ask(prompt, candidates, default=None):
    '''
    Ask the user to choose from a list of candidates, ignoring cases of user
    input.
    '''
    while True:
        reply = raw_input(prompt).lower()
        if reply in candidates:
            return reply
        if reply == '' and default is not None:
            return default
        print('Invalid input, try again')


def mktemp(suffix='', prefix='tmp', dir_=None, text=False,
           mode='w', bufsize=0):
    '''
    Like mkstemp, but returns file object and file name instead of fd and
    file name.

    Accepts extra arguments mode and bufsize to pass to os.fdopen.
    '''
    fd, fname = mkstemp(suffix, prefix, dir_, text)
    fh = os.fdopen(fd, mode, bufsize)
    return fh, fname


def start(uri, binddn, bindpw, starttls=True,
          base='', scope='sub', filterstr='',
          action='edit', ldif=''):
    '''
    Entrance point of ldapvi.

    action is one of 'apply', 'edit', 'list' and 'new'.
    '''
    filterstr = filterstr or '(objectClass=*)'

    def efmt(e):
        msg = e.args[0]
        s = msg['desc']
        if 'info' not in msg:
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

    # Make `old`
    if action in ('apply', 'edit', 'list'):
        old = OrderedDict(sort_entries(conn.search_s(
            base, SCOPES[scope], filterstr)))
    elif action == 'new':
        old = OrderedDict()

    # Prepair LDIF output file
    if action in ('edit', 'new'):
        fldif, fname = mktemp('.ldif')
    elif action == 'list':
        fldif = sys.stdout

    # Write LDIF
    if action in ('edit', 'list'):
        if action == 'list':
            fldif = sys.stdout
        writer = LDIFWriter(fldif)

        for dn, attrs in old.items():
            writer.unparse(dn, attrs)
    elif action in ('apply', 'new'):
        fldif.write(ldif)

    # Read and apply LDIF
    if action in ('apply', 'edit', 'new'):
        fldif.close()
        fire_editor(fname)
        fldif = open(fname)

        parser = LDIFParser(fldif)
        new = parser.parse()
        changes = mkchanges(old, new)

        if not (changes['add'] or changes['modify'] or changes['delete']):
            os.remove(fname)
            print('Nothing changed, discarded LDIF draft %s'
                  ' and exiting' % fname)
            return ''

        msg = 'add %d, modify %d, delete %d. Confirm? [Y/n/q] ' % (
              len(changes['add']), len(changes['modify']),
              len(changes['delete']))

        reply = ask(msg, 'ynq', 'y')
        if reply == 'n':
            print('LDIF draft saved in %s' % fname)
            return 'cancelled'
        elif reply == 'q':
            os.remove(fname)
            print('LDIF draft %s discarded' % fname)
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
    '''
    Command-line interface for start().
    '''
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
                        choices=SCOPES.keys(), default='sub')
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
