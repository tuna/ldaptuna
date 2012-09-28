import os
import sys
from subprocess import check_call, CalledProcessError
from argparse import ArgumentParser
from collections import OrderedDict
from tempfile import mkstemp
from getpass import getpass
from cStringIO import StringIO

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
    'cancel': 3,
    'connect': 4,
    'operate': 7,
    'search': 10,
}


class LDIFParser(ldif.LDIFParser):
    def handle(self, dn, entry):
        self._entries[dn] = entry

    def parse(self):
        self._entries = OrderedDict()
        ldif.LDIFParser.parse(self)
        return self._entries


class LDIFWriter(ldif.LDIFWriter):
    """
    A LDIFWriter with looser criteria for base64 encoding.

    Data is *not* base64-encoded as long as it is valid UTF-8 and contains no
    '\n' or '\r'.

    Line splitting behavior is also reworked to break on Unicode codepoint
    boundaries instead of byte boundaries, *and* based on actual display width
    instead of byte width.
    """
    _unicode_widths = [
        (126,    1), (159,    0), (687,     1), (710,   0), (711,   1),
        (727,    0), (733,    1), (879,     0), (1154,  1), (1161,  0),
        (4347,   1), (4447,   2), (7467,    1), (7521,  0), (8369,  1),
        (8426,   0), (9000,   1), (9002,    2), (11021, 1), (12350, 2),
        (12351,  1), (12438,  2), (12442,   0), (19893, 2), (19967, 1),
        (55203,  2), (63743,  1), (64106,   2), (65039, 1), (65059, 0),
        (65131,  2), (65279,  1), (65376,   2), (65500, 1), (65510, 2),
        (120831, 1), (262141, 2), (1114109, 1),
    ]

    def _unicode_width(self, o):
        if o == 0xe or o == 0xf:
            return 0
        for num, wid in self._unicode_widths:
            if o <= num:
                return wid
        return 1

    def _count_width(self, line):
        w = 0
        for c in line:
            w += self._unicode_width(ord(c))
        return w

    def _unfoldLDIFLine(self, line):
        first = True
        line = line.decode('utf-8')
        sum_width = 0
        s = u''
        all_width = self._count_width(line)
        if all_width <= self._cols:
            self._output_file.write(line.encode('utf-8'))
            self._output_file.write(self._line_sep)
            return
        for c in line:
            wid = self._unicode_width(ord(c))
            minus = 0
            if not first:
                minus = 1
            if sum_width + wid > self._cols - minus:
                if not first:
                    self._output_file.write(' ')
                else:
                    first = False
                self._output_file.write(s.encode('utf-8'))
                self._output_file.write(self._line_sep)
                s = '' + c
                sum_width = wid
            else:
                s += c
                sum_width += wid
        if sum_width > 0:
            self._output_file.write(' ')
            self._output_file.write(s.encode('utf-8'))
            self._output_file.write(self._line_sep)

    def _needs_base64_encoding(self, attr_type, attr_value):
        if attr_type.lower() in self._base64_attrs:
            return True
        try:
            attr_value.decode('utf-8')
            if '\n' in attr_value or '\r' in attr_value:
                return True
            return False
        except UnicodeDecodeError:
            return True


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


class UserCancel(Exception):
    pass


class ActionError(Exception):
    def __init__(self, what, how, e):
        self.what = what
        self.how = how
        self.e = e
        self.message = 'Failed to %s%s:\n    %s' % (what, how, e)

    def __str__(self):
        return self.message


class Action(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def connect(self):
        try:
            self.conn = connect(
                self.uri, self.binddn, self.bindpw, self.starttls)
        except LDAPError as e:
            raise ActionError('connect', ' to %s as %s %s' % (
                self.uri, self.binddn, self.starttls * 'with TLS'), e)

    def mktemp(self):
        return mktemp('.ldif', 'ldaptuna')

    def make_entries(self):
        try:
            entries = OrderedDict(sort_entries(self.conn.search_s(
                self.base, SCOPES[self.scope], self.filterstr)))
        except LDAPError as e:
            raise ActionError('search', ' in %s' % self.base, e)
        return entries

    def write_entries(self, stream, entries):
        writer = LDIFWriter(stream)
        for dn, attrs in entries.items():
            writer.unparse(dn, attrs)

    def read_apply(self, stream, old):
        parser = LDIFParser(stream)
        new = parser.parse()
        changes = mkchanges(old, new)

        if not (changes['add'] or changes['modify'] or changes['delete']):
            print('Nothing changed.')
            return

        msg = 'add %d, modify %d, delete %d. Confirm? [Y/n/q] ' % (
              len(changes['add']), len(changes['modify']),
              len(changes['delete']))

        reply = ask(msg, 'ynq', 'y')
        if reply == 'n':
            raise UserCancel()
        elif reply == 'q':
            return

        for op in 'add', 'modify', 'delete':
            func = getattr(self.conn, '%s_s' % op)
            for change in changes[op]:
                try:
                    func(*change)
                except ldap.LDAPError as e:
                    raise ActionError('operate',
                                      ' to %s %s' % (op, change[0]), e)

    def edit_read_apply(self, fname, old):
        fire_editor(fname)
        stream = open(fname)
        try:
            self.read_apply(stream, old)
        except:
            print('LDIF draft saved in %s' % fname)
            raise
        finally:
            stream.close()

        os.unlink(fname)
        print('Removed %s.' % fname)

    def work(self, base, scope, filterstr, ldif):
        raise NotImplementedError


actions = {}


def register(cls):
    actions[cls.cmd] = cls


@register
class Apply(Action):
    cmd = 'apply'

    def work(self):
        old = self.make_entries()
        self.read_apply(StringIO(self.ldif), old)


@register
class List(Action):
    cmd = 'list'

    def work(self):
        entries = self.make_entries()
        self.write_entries(sys.stdout, entries)


@register
class Edit(Action):
    cmd = 'edit'

    def work(self):
        old = self.make_entries()

        stream, fname = self.mktemp()
        self.write_entries(stream, old)
        stream.close()

        self.edit_read_apply(fname, old)


@register
class New(Action):
    cmd = 'new'

    def work(self):
        stream, fname = self.mktemp()
        stream.write(self.ldif)
        stream.close()

        self.edit_read_apply(fname, OrderedDict())


def start(uri, binddn, bindpw, starttls=True,
          base='', scope='sub', filterstr='',
          action='edit', ldif=''):
    '''
    Entrance point of ldapvi.

    action is one of 'apply', 'edit', 'list' and 'new'.
    '''
    filterstr = filterstr or '(objectClass=*)'

    actor = actions[action](uri=uri, binddn=binddn, bindpw=bindpw,
                            starttls=starttls, base=base, scope=scope,
                            filterstr=filterstr, action=action, ldif=ldif)

    try:
        actor.connect()
        actor.work()
    except ActionError as e:
        print(str(e))
        return e.what
    except UserCancel:
        return 'cancel'

    return ''


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
