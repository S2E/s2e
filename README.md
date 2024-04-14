S2E Library
===========
[![Rebuild the GTISC s2e image](https://github.com/GTISC/s2e/actions/workflows/gtisc_build.yaml/badge.svg)](https://github.com/GTISC/s2e/actions/workflows/gtisc_build.yaml)

This repository contains all the necessary components to build ``libs2e.so``. This shared
library is preloaded in QEMU to enable symbolic execution.


## Set up
1. Install the s2e env
```bash
sudo apt-get install git gcc python3 python3-dev python3-venv

git clone https://github.com/GTISC/s2e-env.git
cd s2e-env

python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip

# By default, s2e-env uses https to clone repositories.
# If you want ssh, please edit s2e_env/dat/config.yaml before running pip install.
# If your key is password-protected, use ssh-agent.
pip install .

# Note: if your pip version is earlier than v19, use the following command:
pip install --process-dependency-links .
```
2. Create a new s2e enviroment: `s2e init /your/dir`.
3. Build s2e: `s2e build`.
4. Check `https://s2e.systems/docs/Testsuite.html` to see how to run some test programs.

## 
Please refer to the documentation in the ``docs`` directory for build and usage instructions.
You can also find it online on <https://s2e.systems/docs>.

