# ================
# Image that only sets the envs
FROM ubuntu:22.04 as env-base
ENV TZ=Etc/UTC
ENV PATH=$PATH:/home/s2e/.local/bin
ENV TERM=xterm-256color

# ================
# Base image: needed for both building and running
FROM env-base as base

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y --fix-missing qemu qemu-kvm git curl wget lsb-release sudo gcc python3 python3-dev python3-venv python3-pip python-is-python3

RUN useradd -m s2e && echo "s2e:s2e" | chpasswd && adduser s2e sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER s2e

# install s2e-env for building and running s2e
RUN cd /home/s2e && git clone https://github.com/GTISC/s2e-env.git \
    && cd /home/s2e/s2e-env && pip install --upgrade pip && pip install .


# ================
# First stage: build s2e
FROM base as builder

ARG TARGET_BRANCH=master
RUN s2e init /home/s2e/s2e -sb $TARGET_BRANCH
WORKDIR /home/s2e/s2e
SHELL ["/bin/bash", "-c"]
RUN source s2e_activate
RUN s2e update
RUN s2e build

# clean up
RUN sudo rm -rf build source/.repo source/s2e-linux-kernel source/s2e-env source/s2e source/qemu

# ================
# Second stage: copy over the built s2e
FROM base as deploy

# We need to install two more things to make it work: jq and libmagic1
# They are probably installed by `s2e build`
RUN sudo apt update && sudo apt install -y jq libmagic1

COPY --from=builder /home/s2e/s2e /home/s2e/s2e
# We also have to copy the libs, otherwise, qemu won't work
COPY --from=builder /usr/lib/x86_64-linux-gnu/ /usr/lib/x86_64-linux-gnu/

# ================
# Third stage: flatten everything from deploy into one layer to further reduce the size
FROM env-base
COPY --from=deploy / /
USER s2e
WORKDIR /home/s2e