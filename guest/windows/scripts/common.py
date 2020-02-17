# Copyright (C) 2017, Cyberhaven
# Copyright (C) 2017, Dependable Systems Laboratory, EPFL
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



import argparse
import os
import subprocess

import jinja2
import pefile


def filter_hex(value):
    try:
        return '%#x' % value
    except:
        return value


def LOWORD(dword):
    return dword & 0x0000ffff


def HIWORD(dword):
    return dword >> 16


class PdbParser(object):
    def __init__(self, pdb_parser, exe_file, pdb_file):
        self._pdb_parser = pdb_parser
        self._exe = exe_file
        self._pdb = pdb_file
        self._pe = pefile.PE(exe_file)

    def get_function_address(self, function, allow_null=False):
        cmd = [self._pdb_parser, '-f', function, self._exe, self._pdb]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        ret = proc.stdout.readline().rstrip().split()
        if len(ret) != 3:
            if allow_null:
                return 0
            else:
                raise RuntimeError('Function %s does not exist in %s' %
                                   (function, self._pdb))

        return int(ret[2], 16)

    def get_field_offset(self, type_name):
        cmd = [self._pdb_parser, '-t', type_name, self._exe, self._pdb]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        ret = proc.stdout.readline().rstrip().split()
        if len(ret) == 3:
            return int(ret[2], 16)

        return None

    @property
    def product_version(self):
        ms = self._pe.VS_FIXEDFILEINFO[0].ProductVersionMS
        ls = self._pe.VS_FIXEDFILEINFO[0].ProductVersionLS

        return HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls)

    @property
    def checksum(self):
        return self._pe.OPTIONAL_HEADER.CheckSum

    @property
    def native_base(self):
        return self._pe.OPTIONAL_HEADER.ImageBase

    @property
    def bits(self):
        if self._pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return 32
        elif self._pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return  64
        else:
            raise Exception('Machine not supported')

    @property
    def syscalls(self):
        cmd = [self._pdb_parser, '-s', self._exe, self._pdb]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        ret = proc.stdout.readlines()
        syscalls = []
        for l in ret:
            _, addr, name = l.split()
            syscalls.append((addr, name))
        return syscalls


def extract_info(pdbparser, directory, cb):
    result = []

    files = os.listdir(directory)
    for f in files:
        if '.pdb' not in f:
            continue

        pdb_file = os.path.join(directory, f)
        exe_file = pdb_file.replace('.pdb', '.exe')
        if not os.path.isfile(exe_file):
            print('Could not find %s' % exe_file)
            continue

        parser = PdbParser(pdbparser, exe_file, pdb_file)
        info = cb(parser)
        if info is not None:
            info['file'] = os.path.basename(pdb_file)
            result.append(info)
            print('Processing %s %s' % (f, info['version']))

    return sorted(result, key=lambda x: x['version'])


def extract(cb, template_name):
    parser = argparse.ArgumentParser(description='Downloads symbol files.')

    parser.add_argument('-d', '--directory', dest='directory', required=True,
                        help='Directory cointaining all EXE and PDB files of Windows kernels')
    parser.add_argument('-p', '--pdbparser', dest='pdbparser', required=True,
                        help='Path to pdbparser.exe binary')
    parser.add_argument('-o', '--output', dest='output', required=True,
                        help='Path to the output file')

    args = parser.parse_args()

    for p in [args.directory, args.pdbparser]:
        if not os.path.exists(p):
            print('%s does not exist' % p)
            return

    data = extract_info(args.pdbparser, args.directory, cb)

    jinja_environment = jinja2.Environment(trim_blocks=True,
            loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))
    jinja_environment.filters['hex'] = filter_hex
    template = jinja_environment.get_template(template_name)
    ret = template.render({'data': data})

    with open(args.output, 'w') as fp:
        fp.write(ret)
