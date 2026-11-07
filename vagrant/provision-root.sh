#!/bin/sh
# Copyright (C) 2021 Vitaly Chipounov
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


set -xe
pwd
ls -la
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y install xfsprogs

if ! findmnt /mnt/disk; then
    mkfs.xfs /dev/vdb
    mkdir /mnt/disk
    mount /dev/vdb /mnt/disk
fi

apt-get -y install git gcc python3 python3-dev python3-venv podman uidmap

# Podman 4.3 on Debian 12 defaults to the vfs storage driver, which stores a full
# copy of every image layer. The kernel's overlay driver works rootless there.
if grep -q '^VERSION_ID="12"' /etc/os-release && grep -q '^ID=debian' /etc/os-release; then
    mkdir -p /etc/containers
    printf '[storage]\ndriver = "overlay"\n' > /etc/containers/storage.conf
fi

# The Ubuntu image doesn't have enough space on the boot partition to install some packages.
# Cleanup unused kernels.
if uname -a | grep -q ubuntu2004; then
    apt-get -y remove linux-image-5.4.0-42-generic linux-headers-5.4.0-42-generic linux-modules-5.4.0-42-generic
fi

chown -R vagrant:vagrant /mnt/disk/

# Rootless Podman needs the user's systemd instance and its session bus. The
# instance may have started before apt-get installed dbus-user-session, so it is
# restarted to create /run/user/UID/bus. Lingering keeps it running without a
# login session, which su does not create.
loginctl enable-linger vagrant
systemctl restart "user@$(id -u vagrant)"

# su without "-" keeps the environment, so the *_BRANCH variables that the
# Vagrantfile passes reach provision-user.sh.
su -c "/bin/bash -c 'source /vagrant/provision-user.sh'" vagrant
