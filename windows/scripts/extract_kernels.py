#!/usr/bin/env python

# Copyright (C) 2017, Adrian Herrera
# All rights reserved.
#
# Licensed under the MIT License.

"""
Extracts Windows kernel executables (typically ``ntoskrnl.exe``) from an ISO.
This is useful when updating the ``winmonitor_gen.c`` file, as the kernel
executable is used to generate the correct data structure offsets for that
particular kernel.

Usage
-----

::

    python extract_kernels.py -d /path/to/isos -o /path/to/output

Where ``isos`` is a directory containing all or some of the supported ISOs
listed in s2e/guest-images/images.json and ``output`` is the directory to store
the kernel executable files.

Requirements
------------

Requires 7-Zip version 9.30 or newer (http://www.7-zip.org/) and that the
``7z`` executable is available on the ``PATH``.

This script will work with both Python 2.7 and 3.x.
"""


from __future__ import print_function


import argparse
import hashlib
import os
import re
import shutil
import subprocess

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

import sys
import tempfile


SEVEN_ZIP_VERSION_REGEX = re.compile(r'7-Zip .*?(?P<major>\d+)\.(?P<minor>\d+)')


# Maps Windows ISOs (taken from the supported images listed in
# s2e/guest-images/images.json) to the location of the kernel within the ISO.
#
# The kernel executable is typically stored within an intermediary container.
# The path to this intermediary container is the mapped value in this
# dictionary.
KRNL_CONTAINER_MAP = {
    'en_windows_xp_professional_with_service_pack_3_x86_cd_x14-80428.iso':
        [os.path.join('I386', '*.EX_')],
    'en_windows_7_enterprise_with_sp1_x64_dvd_u_677651.iso':
        [os.path.join('sources', 'install.wim')],
    'en_windows_8_1_enterprise_x64_dvd_2971902.iso':
        [os.path.join('sources', 'install.wim')],
    'en_windows_10_enterprise_version_1703_updated_march_2017_x64_dvd_10189290.iso':
        [os.path.join('sources', 'install.wim')],
}

# We use the wildcard pattern "nt*.exe" to find kernel executables in a Windows
# ISO. Unforuntaly, this can also match other executables that are not related
# to the kernel. A blacklist of these executables is maintained here.
NT_BLACKLIST = [
    'ntprint.exe',
    'ntbackup.exe',
    'ntvdm.exe',
]


# Adapted from http://stackoverflow.com/a/19299884/5894531
class TemporaryDirectory(object):
    """
    Create and return a temporary directory.  This has the same behavior as
    mkdtemp but can be used as a context manager. For example:

        with TemporaryDirectory() as tmpdir:
            ...

    Upon exiting the context, the directory and everything contained in it are
    removed.
    """

    def __init__(self, suffix='', prefix='tmp', dir_=None):
        self._closed = False
        self.name = None
        self.name = tempfile.mkdtemp(suffix, prefix, dir_)

    def __repr__(self):
        return '<{} {!r}>'.format(self.__class__.__name__, self.name)

    def __enter__(self):
        return self.name

    def __exit__(self, exc, value, tb):
        self.cleanup()

    def __del__(self):
        self.cleanup(warn=True)

    def cleanup(self, warn=False):
        if self.name and not self._closed:
            try:
                shutil.rmtree(self.name)
            except Exception as e:
                print('ERROR: {!r} while cleaning up {!r}'.format(e, self),
                      file=sys.stderr)
                return

            self._closed = True
            if warn:
                print('Implicitly cleaning up {!r}'.format(self))


def parse_args():
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser(description='Extract Windows kernels.')
    parser.add_argument('-d', '--iso-dir', required=True,
                        help='Path to the directory containing the ISOs')
    parser.add_argument('-o', '--output-dir', default=os.getcwd(),
                        help='Directory to store the extract kernels. '
                             'Defaults to the current working directory')

    return parser.parse_args()


def seven_zip_version():
    """Get the 7-Zip version number."""
    proc = subprocess.Popen(['7z'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()

    if proc.returncode:
        return None

    m = SEVEN_ZIP_VERSION_REGEX.search(stdout)
    if not m:
        return None

    return int(m.group('major')), int(m.group('minor'))


def seven_zip_extract(source, wildcard_includes, wildcard_excludes=None,
                      dest=None):
    """
    Execute 7-Zip and extract the files from `source` that match the given
    include wildcard patterns. A list of exclusion wldcard patterns may
    optionally be given.
    """
    if not dest:
        dest = os.getcwd()

    # Assemble the 7-Zip command-line arguments
    args = ['7z', 'e', '-aou']

    for wildcard_inc in wildcard_includes:
        args.append('-ir!%s' % wildcard_inc)

    if not wildcard_excludes:
        wildcard_excludes = []

    for wildcard_exc in wildcard_excludes:
        args.append('-xr!%s' % wildcard_exc)

    args.append(source)

    # Run 7-Zip
    proc = subprocess.Popen(args, stdout=DEVNULL, stderr=subprocess.PIPE,
                            cwd=dest)
    _, stderr = proc.communicate()

    return proc.returncode, stderr


def calc_hash(path):
    """Calculate the hash of the file at the given location."""
    with open(path, 'r') as f:
        return hashlib.md5(f.read()).hexdigest()

    # XXX Throw exception?
    return ''



def main():
    """The main function."""
    args = parse_args()

    iso_dir = args.iso_dir
    if not os.path.isdir(iso_dir):
        raise Exception('%s is not a valid ISO directory' % iso_dir)

    output_dir = args.output_dir
    if not os.path.isdir(output_dir):
        raise Exception('%s is not a valid output directory' % output_dir)

    iso_dir = os.path.realpath(iso_dir)
    output_dir = os.path.realpath(output_dir)

    # Check the version of 7-Zip available
    seven_zip_ver = seven_zip_version()
    if not seven_zip_ver:
        print(u'[\u2717] Unable to determine 7-Zip version. Some kernels may '
              u'not be extracted')
    elif(seven_zip_ver[0] < 9 or
         (seven_zip_ver[0] == 9 and seven_zip_ver[1] < 30)):
        print(u'[\u2717] This version of 7-Zip (%d.%d) is unable to extract '
              u'WIM images from Windows 8 or newer - no kernels will be '
              u'extracted from those ISOs.\n    7-Zip 9.30 or newer is '
              u'required to extract files from Windows 8 WIM '
              u'images' % (seven_zip_ver[0], seven_zip_ver[1]))

    # Maintain a set of hashes for kernels that we've already extraced. This is
    # to prevent extracting the same kernel multiple times
    krnl_hashes = set()

    for iso, containers in KRNL_CONTAINER_MAP.items():
        iso_path = os.path.join(iso_dir, iso)
        if not os.path.isfile(iso_path):
            print(u'[\u2717] %s does not exist. Skipping...' % iso)
            continue

        iso_name, _ = os.path.splitext(iso)

        with TemporaryDirectory() as temp_dir:
            print('[-] Extracting kernels from %s...' % iso)

            for container in containers:
                print('[-]   Looking for kernels in %s...' % container)

                # Extract the kernel container
                returncode, stderr = seven_zip_extract(iso_path, [container],
                                                       dest=temp_dir)
                if returncode:
                    print(u'[\u2717]   Failed to extract %s from %s: "%s"' %
                          (container, iso, stderr))
                    continue

                container_name = os.path.basename(container)
                container_path = os.path.join(temp_dir, container_name)

                # Extract the kernel executable(s)
                returncode, stderr = seven_zip_extract(container_path,
                                                       ['nt*.exe'],
                                                       NT_BLACKLIST, temp_dir)
                if returncode:
                    print(u'[\u2717]     Failed to extract kernels from %s: '
                          u'"%s"' % (container, stderr))
                    continue

                # Copy the extracted kernels from the temporary directory to
                # the given output directory
                for root, _, files in os.walk(temp_dir):
                    for file_ in files:
                        # The kernel will be an executable file
                        _, file_ext = os.path.splitext(file_)
                        if file_ext != '.exe':
                            continue

                        # The output file is named after the ISO, hash of the
                        # file and the original file name
                        krnl_path = os.path.join(root, file_)
                        krnl_hash = calc_hash(krnl_path)

                        # If we've already saved this kernel, ignore it
                        if krnl_hash in krnl_hashes:
                            continue

                        output_file = '%s_%s_%s' % (iso_name, krnl_hash, file_)
                        output_path = os.path.join(output_dir, output_file)

                        shutil.move(krnl_path, output_path)

                        krnl_hashes.add(krnl_hash)

                        print(u'[\u2713]     Successfully extracted %s to %s' %
                              (file_, output_file))


if __name__ == '__main__':
    main()
