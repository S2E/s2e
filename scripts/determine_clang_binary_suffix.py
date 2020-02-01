#!/usr/bin/env python3

# Copyright (C) 2018 Adrian Herrera
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Inspects the current operating system and determines which Clang binary to
download. If a valid version is found, the suffix of the file to download is
printed to stdout. Otherwise an error message is printed to stderr.

Note: This script is only really meant to be used by the S2E Makefile. It has
no real use outside of this.
"""

import platform
import sys


# Supported operating systems for Clang binary downloads
SUPPORTED_OS = ('ubuntu', 'debian')


def eprint(*args, **kwargs):
    """Print to stderr and exit."""
    print(*args, file=sys.stderr, **kwargs)
    sys.exit(1)


def _get_debian_version(version_string):
    """
    Determine the Clang binary to download from the version string returned by
    ``platform.linux_distribution``.
    """
    version = int(version_string)

    if version >= 8:
        return 'x86_64-linux-gnu-debian8'
    else:
        return None


def _get_ubuntu_version(version_string):
    """
    Determine the Clang binary to downoad from the version string returned by
    ``platform.linux_distribution``.
    """
    major_version, minor_version = list(map(int, version_string.split('.')))

    # Currently S2E only supports LLVM 3.9.1, and the only Clang binary
    # packages that exist for this version are for Ubuntu 14.04 and 16.04
    if major_version == 14 and minor_version >= 4:
        return 'x86_64-linux-gnu-ubuntu-14.04',
    elif major_version == 15:
        return 'x86_64-linux-gnu-ubuntu-14.04',
    elif major_version == 16 and minor_version >= 4:
        return 'x86_64-linux-gnu-ubuntu-16.04',
    elif major_version == 18:
        return 'x86_64-linux-gnu-ubuntu-18.04',
    else:
        return None


def main():
    """The main function."""
    distro, version, _ = platform.linux_distribution()

    clang_ver_to_download = None
    if distro.lower() == 'debian':
        clang_ver_to_download = _get_debian_version(version)
    elif distro.lower() == 'ubuntu':
        clang_ver_to_download = _get_ubuntu_version(version)
    else:
        eprint('Linux distro %s is not supported' % distro)

    if clang_ver_to_download:
        print('%s' % clang_ver_to_download)
    else:
        eprint('%s %s is not supported' % (distro, version))


if __name__ == '__main__':
    main()
