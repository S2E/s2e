#!/usr/bin/env python

# Copyright (C) 2017, Adrian Herrera
# Copyright (C) 2018, Cyberhaven
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

import argparse
import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

SEVEN_ZIP_VERSION_REGEX = re.compile(r'7-Zip .*?(?P<major>\d+)\.(?P<minor>\d+)')

NT_PATTERN = re.compile(r'(ntoskrnl|ntkrnlmp|ntkrnlpa)$')

# This will work only on msys
EXPAND_PATH = '/c/Windows/System32/expand.exe'

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

    m = SEVEN_ZIP_VERSION_REGEX.search(stdout.decode())
    if not m:
        return None

    return int(m.group('major')), int(m.group('minor'))

def seven_zip_extract(source, wildcard_includes, wildcard_excludes=None,
                      dest_dir=None):
    """
    Execute 7-Zip and extract the files from `source` that match the given
    include wildcard patterns. A list of exclusion wildcard patterns may
    optionally be given.
    """
    if not dest_dir:
        dest_dir = os.getcwd()

    # Assemble the 7-Zip command-line arguments
    args = ['7z', 'e', '-aou']

    for wildcard_inc in wildcard_includes:
        args.append('-ir!%s' % wildcard_inc)

    if not wildcard_excludes:
        wildcard_excludes = []

    for wildcard_exc in wildcard_excludes:
        args.append('-xr!%s' % wildcard_exc)

    args.append(source)

    print('    [\u00b7] %s - %s' % (' '.join(args), dest_dir))

    # Run 7-Zip
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=dest_dir)
    _, stderr = proc.communicate()

    if proc.returncode:
        raise Exception('[\u2717] Failed to extract file %s from %s: "%s"' % (wildcard_includes, source, stderr))

# We can't use 7z to extract files from CABs because some files inside may use delta encoding.
# Such a cab file would contain XML files describing the various chunks of a file.
# 7z would get us the chunks and we need the reassembled files.
def cab_extract(source, dest_dir, pattern='*'):
    args = [EXPAND_PATH, source, '-F:%s' % (pattern), dest_dir]

    print('    [\u00b7] %s - %s' % (' '.join(args), dest_dir))

    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=dest_dir)
    stdout, stderr = proc.communicate()

    if proc.returncode:
        raise Exception('[\u2717] Failed to extract files from %s: "%s %s"' % (source, stdout, stderr))

def seven_zip_list(source):
    # A filename line has 6 elements on it
    ELEM_COUNT = 6

    # This is the relative path of the file
    FILE_PATH_INDEX = 5

    args = ['7z', 'l', source]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()

    files = []

    for line in stdout.decode().splitlines():
        els = line.split()
        if len(els) == ELEM_COUNT:
            files.append(els[FILE_PATH_INDEX])

    return files

def calc_hash(path):
    """Calculate the hash of the file at the given location."""
    with open(path, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def check_7z_version():
    seven_zip_ver = seven_zip_version()
    if not seven_zip_ver:
        print('[\u2717] Unable to determine 7-Zip version. Some kernels may '
              'not be extracted')
    elif (seven_zip_ver[0] < 9 or (seven_zip_ver[0] == 9 and seven_zip_ver[1] < 30)):
        print('[\u2717] This version of 7-Zip (%d.%d) is unable to extract '
              'WIM images from Windows 8 or newer - no kernels will be '
              'extracted from those ISOs.\n    7-Zip 9.30 or newer is '
              'required to extract files from Windows 8 WIM '
              'images' % (seven_zip_ver[0], seven_zip_ver[1]))

def check_expand():
    if not os.path.exists(EXPAND_PATH):
        print('[\u2717] Could not find %s. It is required in order to '
              'extract kernels from *.msu files.' % EXPAND_PATH)
        return False

    return True

def get_full_name(container_path, filepath):
    hashvalue = calc_hash(filepath)
    basename = os.path.basename(filepath)
    container, _ = os.path.splitext(os.path.basename(container_path))

    return '%s_%s_%s' % (container, hashvalue, basename)

# Quick and dirty method to ensure that a kernel is not extracted twice.
# Note that this script may be called several times with subset of kernels,
# so we need to check the file system.
def kernel_already_extracted(output_dir, filepath):
    hashvalue = calc_hash(filepath)

    files = get_files_in_dir(output_dir)
    for f in files:
        if hashvalue in f:
            return True

    return False

def get_base_name(path):
    filename = os.path.basename(path)
    base, _ = os.path.splitext(filename)
    return base

def filter_kernels(files):
    ret = []

    for f in files:
        base = get_base_name(f.lower())

        if NT_PATTERN.match(base):
            ret.append(f)

    return ret

def extract_file(output_dir, container, source):
    source_name = os.path.basename(source)

    with TemporaryDirectory() as temp_dir:
        seven_zip_extract(container, [source], dest_dir=temp_dir)
        return expand_file(output_dir, os.path.join(temp_dir, source_name))

def expand_file(output_dir, filepath):
    filename = os.path.basename(filepath).lower()
    if not filename.endswith('.ex_'):
        dest_path = os.path.join(output_dir, filename)
        os.rename(filepath, dest_path)
        return dest_path

    dest_path = os.path.join(output_dir, filename.replace('.ex_', '.exe'))
    with TemporaryDirectory() as temp_dir:
        seven_zip_extract(filepath, [], dest_dir=temp_dir)
        f = glob.glob(os.path.join(temp_dir, '*.exe'))[0]
        os.rename(f, dest_path)

    return dest_path

def is_valid_kernel(path):
    with open(path, 'rb') as fp:
        b = fp.read(2)
        return b == b'MZ'

def get_files_in_dir(directory):
    ret = []

    for root, _, files in os.walk(directory):
        for f in files:
            filepath = os.path.join(root, f)
            ret.append(filepath)

    return ret

def extract_kernels_from_container(output_dir, container, files):
    container_is_dir = os.path.isdir(container)
    kernels = filter_kernels(files)

    for kernel in kernels:
        if container_is_dir:
            new_name = get_full_name(container, kernel)
            final_path = os.path.join(output_dir, new_name)
            dest_path = kernel
        else:
            dest_path = extract_file(output_dir, container, kernel)
            new_name = get_full_name(container, dest_path)
            final_path = os.path.join(output_dir, new_name)

        if not is_valid_kernel(dest_path):
            print('    [\u2717] %s is not a valid kernel' % dest_path)
            os.remove(dest_path)
        elif kernel_already_extracted(output_dir, dest_path):
            print('    [\u2717] %s has already been extracted' % final_path)
            os.remove(dest_path)
        else:
            os.rename(dest_path, final_path)
            print('    [\u2713] Extracted %s' % final_path)

def extract_kernels_wim(output_dir, iso_file):
    iso_basename, _ = os.path.splitext(os.path.basename(iso_file))

    with TemporaryDirectory() as temp_dir:
        seven_zip_extract(iso_file, ['sources/install.wim'], dest_dir=temp_dir)
        wim = os.path.join(temp_dir, 'install.wim')

        # Rename the wim to have more informative kernel name
        dest_wim = os.path.join(temp_dir, '%s.wim' % iso_basename)
        os.rename(wim, dest_wim)

        files = seven_zip_list(dest_wim)
        extract_kernels_from_container(output_dir, dest_wim, files)

def extract_kernels_from_iso(output_dir, iso_file):
    # First, guess the OS version we have.
    # Windows XP has an I386 folder, while later ones contain install.wim
    files = seven_zip_list(iso_file)

    if 'sources/install.wim' in files:
        # Extract the wim, then extract files from that wim
        extract_kernels_wim(output_dir, iso_file)
    elif 'WIN51' in files:
        extract_kernels_from_container(output_dir, iso_file, files)
    else:
        print('    [\u2717] Invalid install iso')

def extract_kernels_from_msu(output_dir, msu_file):
    if not check_expand():
        return

    with TemporaryDirectory() as temp_dir:
        seven_zip_extract(msu_file, ['*.cab'], dest_dir=temp_dir)
        for root, _, files in os.walk(temp_dir):
            for f in files:
                filepath = os.path.join(root, f)

                with TemporaryDirectory(prefix=f) as cab_dir:
                    # We could also add support for cab files to extract_kernels_from_container,
                    # but given the low number of files in MSU files, just extract everything
                    # and filter afterwards.
                    cab_extract(filepath, cab_dir, '*.exe')
                    files = get_files_in_dir(cab_dir)
                    extract_kernels_from_container(output_dir, cab_dir, files)

def extract_kernels(output_dir, filepath):
    print('Extracting kernels from %s to %s' % (filepath, output_dir))

    _, ext = os.path.splitext(filepath)
    if ext == '.iso':
        extract_kernels_from_iso(output_dir, filepath)
    elif ext == '.msu':
        extract_kernels_from_msu(output_dir, filepath)
    elif ext == '.wim':
        files = seven_zip_list(filepath)
        extract_kernels_from_container(output_dir, filepath, files)
    else:
        print('    [\u2717] Unknown file type: %s' % ext)

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
    check_7z_version()

    for root, _, files in os.walk(iso_dir):
        for f in files:
            filepath = os.path.join(root, f)
            extract_kernels(output_dir, filepath)

if __name__ == '__main__':
    main()
