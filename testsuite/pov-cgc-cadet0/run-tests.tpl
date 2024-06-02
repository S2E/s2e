#!/usr/bin/env python

import atexit
import ctypes.util
import glob
import os
import signal
import subprocess
import sys
import time

libc = ctypes.CDLL(ctypes.util.find_library('c'))

# This will be replaced during template instantiation
PROJECT_NAME = '{{ project_name }}'

g_success = False


def on_exit(s2e_last):
    with open(os.path.join(s2e_last, 'status'), 'w') as fp:
        fp.write('SUCCESS\n' if g_success else 'FAILURE\n')


def send_signal_to_children_on_exit(sig):
    # Make sure that s2e would get killed if the parent process crashes
    # 1 = PR_SET_PDEATHSIG
    libc.prctl(1, sig, 0, 0, 0)


def check_recipes(directory):
    for p in ['recipe-type1_i386_generic_reg', 'recipe-type1_i386_generic_shellcode', 'recipe-type2_i386_decree_shellcode']:
        files = glob.glob('%s/*%s*' % (directory, p))
        if files:
            print('Found %s' % p)
        else:
            return False

    return True

def run_s2e(*args):
    s2e = subprocess.Popen(args, stdout=sys.stdout, stderr=sys.stderr)

    # Wait for the process to start.
    # If s2e-last symlink is already present with old test results,
    # we might find stale PoVs and exit the script prematurely.
    time.sleep(5)

    return s2e


def poll_recipes(s2e, directory):
    while not s2e.poll():
        print('Waiting for recipes...')
        if check_recipes(directory):
            return True

        time.sleep(5)

    return False

def verify_pov():
    cwd = os.path.dirname(__file__)
    verifier_path = os.path.join(cwd, 'verify-pov.sh')
    verifier = subprocess.Popen(verifier_path, stdout=sys.stdout, stderr=sys.stderr, cwd=cwd)
    while verifier.poll() is None:
        print('Waiting for verifier...')
        time.sleep(1)

    return verifier.returncode == 0


def main():
    if not os.getenv('S2EDIR'):
        print('Please set S2EDIR to the root of the S2E environement before starting this script')
        sys.exit(-1)

    s2e_last = os.path.join(os.path.dirname(__file__), 's2e-last')

    atexit.register(on_exit, s2e_last)
    send_signal_to_children_on_exit(signal.SIGKILL)

    global g_success

    recipes_ok = False
    pov_verified = False

    try:
        s2e = run_s2e('s2e', 'run', '-n', PROJECT_NAME)
        recipes_ok = poll_recipes(s2e, s2e_last)
        s2e.terminate()

        try:
            pov_verified = verify_pov()
        except Exception as e:
            print('Caught exception %s' % e)

        g_success = recipes_ok and pov_verified
    except Exception as e:
        print('Caught exception %s' % e)
    finally:
        if g_success:
            sys.exit(0)
        else:
            sys.exit(-1)


if __name__ == "__main__":
    main()
