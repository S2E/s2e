#!/usr/bin/env python

"""
Download debugging symbols from the Microsoft Symbol Server.
Can use as an input an executable file OR a GUID+Age and filename.
Examples:

$ python symcheck.py -e ntoskrnl.exe

$ python symchk.py -g 32962337f0f646388b39535cd8dd70e82 -s ntoskrnl.pdb
The GUID+Age here corresponds to the kernel version of the xp-laptop-2005-* images
The Age value is 0x2.


Module Dependencies:
This script requires the following modules:
pefile - http://code.google.com/p/pefile/
construct - http://construct.wikispaces.com/
To decompress downloaded files you should also have cabextract on your system.
http://www.cabextract.org.uk/

License:
GPL version 3
http://www.gnu.org/licenses/gpl.html

Miscellaneous References:
You can see an explanation of the URL format at:
http://jimmers.info/pdb.html
"""



import argparse
import os
import shutil
import sys
import tempfile
import urllib.request, urllib.error, urllib.parse

import requests

from pyunpack import Archive
from urllib.request import FancyURLopener
from pdbparse.peinfo import *


#SYM_URL = 'http://symbols.mozilla.org/firefox'
SYM_URLS = ['http://msdl.microsoft.com/download/symbols']
USER_AGENT = 'Microsoft-Symbol-Server/6.6.0007.5'


class PDBOpener(FancyURLopener):
    version = USER_AGENT

    def http_error_default(self, url, fp, errcode, errmsg, headers):
        if errcode == 404:
            raise urllib.error.HTTPError(url, errcode, errmsg, headers, fp)
        else:
            FancyURLopener.http_error_default(url, fp, errcode, errmsg, headers)


lastprog = None
def progress(blocks, blocksz, totalsz):
    global lastprog
    if lastprog is None:
        print('Connected. Downloading data...')
    percent = int((100 * (blocks * blocksz) / float(totalsz)))
    if lastprog != percent and percent % 5 == 0:
        print('%d%%' % percent)
    lastprog = percent
    sys.stdout.flush()


def download(url, path):
    print('Downloading %s to %s' % (url, path))
    r = requests.get(url)
    r.raise_for_status()

    with open(path, 'wb') as fp:
        fp.write(r.content)


def download_file(guid, fname, path='', quiet=False):
    """
    Download the symbols specified by guid and filename. Note that 'guid'
    must be the GUID from the executable with the dashes removed *AND* the
    Age field appended. The resulting file will be saved to the path argument,
    which default to the current directory.
    """

    # A normal GUID is 32 bytes. With the age field appended
    # the GUID argument should therefore be longer to be valid.
    # Exception: old-style PEs without a debug section use
    # TimeDateStamp+SizeOfImage
    if len(guid) == 32:
        print('Warning: GUID is too short to be valid. Did you append the Age field?')

    for sym_url in SYM_URLS:
        url = '%s/%s/%s/' % (sym_url, fname, guid)

        # Whatever extension the user has supplied it must be replaced with .pd_
        tries = [fname[:-1] + '_', fname]

        for t in tries:
            if not quiet:
                print('Trying %s' % (url + t))
            outfile = os.path.join(path, t)
            try:
                # hook = None if quiet else progress
                # This seems broken, replace with plane http request
                # PDBOpener().retrieve(url+t, outfile, reporthook=hook)
                download(url + t, outfile)

                if not quiet:
                    print('Saved symbols to %s' % outfile)
                return outfile
            except urllib.error.HTTPError as e:
                if not quiet:
                    print('HTTP error %u' % e.code)
            except IOError as e:
                if not quiet:
                    print('File error %s' % e)
    return None


def handle_pe(pe_file, quiet=True):
    dbgdata, tp = get_pe_debug_data(pe_file)
    if tp == 'IMAGE_DEBUG_TYPE_CODEVIEW':
        # XP+
        if dbgdata[:4] == b'RSDS':
            guid, filename = get_rsds(dbgdata)
        elif dbgdata[:4] == b'NB10':
            guid, filename = get_nb10(dbgdata)
        else:
            print('ERR: CodeView section not NB10 or RSDS')
            return
        guid = guid.upper()
        saved_file = download_file(guid, filename, quiet=quiet)
    elif tp == 'IMAGE_DEBUG_TYPE_MISC':
        # Win2k
        # Get the .dbg file
        guid = get_pe_guid(pe_file)
        guid = guid.upper()
        filename = get_dbg_fname(dbgdata)
        saved_file = download_file(guid, filename, quiet=quiet)

        # Extract it if it's compressed
        # Note: requires cabextract!
        if saved_file.endswith('_'):
            os.system('cabextract %s' % saved_file)
            saved_file = saved_file.replace('.db_', '.dbg')

        from pdbparse.dbgold import DbgFile
        dbgfile = DbgFile.parse_stream(open(saved_file))
        cv_entry = [d for d in dbgfile.IMAGE_DEBUG_DIRECTORY
                    if d.Type == b'IMAGE_DEBUG_TYPE_CODEVIEW'][0]
        if cv_entry.Data[:4] == b'NB09':
            return
        elif cv_entry.Data[:4] == b'NB10':
            guid, filename = get_nb10(cv_entry.Data)

            guid = guid.upper()
            saved_file = download_file(guid, filename, quiet=quiet)
        else:
            print('WARN: DBG file received from symbol server has unknown CodeView section')
            return
    else:
        print('Unknown type: %s' % tp)
        return

    _, extension = os.path.splitext(pe_file)
    new_file = pe_file.replace(extension, '.pdb')

    if saved_file.endswith('_'):
        print('Unpacking to %s' % new_file)
        unpack_file(saved_file, new_file)
        os.unlink(saved_file)
    else:
        print('Renaming file to %s' % new_file)
        os.rename(saved_file, new_file)


def unpack_file(source, dest):
    dirname = tempfile.mkdtemp()
    Archive(source).extractall(dirname)

    for root, _, files in os.walk(dirname, topdown=False):
        for name in files:
            path = os.path.join(root, name)
            os.rename(path, dest)

    shutil.rmtree(dirname, True)


def main():
    parser = argparse.ArgumentParser(description='Downloads symbol files.')

    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('exe', help='The executable to download symbols for')

    args = parser.parse_args()
    if not os.path.exists(args.exe):
        print('%s does not exist' % args.exe)
        return

    handle_pe(args.exe, not args.verbose)


if __name__ == '__main__':
    main()
