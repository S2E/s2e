# ================
# Base image: needed for both building and running
FROM ubuntu:22.04 AS base

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV PATH=$PATH:/home/s2e/.local/bin
ENV TERM=xterm-256color


RUN apt update
RUN apt install -y --fix-missing qemu sudo qemu-kvm git curl wget lsb-release gcc python3 python3-dev python3-venv python3-pip jq libmagic1 libsdl1.2-dev fuse3
RUN apt install -y python-is-python3
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN useradd -m s2e && echo "s2e:s2e" | chpasswd && adduser s2e sudo
USER s2e
WORKDIR /home/s2e

RUN git clone https://github.com/GTISC/s2e-env.git
WORKDIR /home/s2e/s2e-env
RUN pip install --upgrade pip
RUN pip install .

# ================
# First stage: build s2e

FROM base AS builder
ARG TARGET_BRANCH=master
RUN s2e init /home/s2e/s2e -sb $TARGET_BRANCH
WORKDIR /home/s2e/s2e
SHELL ["/bin/bash", "-c"]
RUN source s2e_activate
RUN s2e update
RUN s2e build

# ================
# Second stage: copy over the built s2e
FROM base AS runner
# Copy the built s2e deps
COPY --from=builder /home/s2e/s2e/install /home/s2e/s2e/install
COPY --from=builder /home/s2e/s2e/s2e.yaml /home/s2e/s2e/s2e.yaml
COPY --from=builder /home/s2e/s2e/s2e_activate /home/s2e/s2e/s2e_activate
COPY --from=builder /home/s2e/s2e/source /home/s2e/s2e/source
# We also have to copy the libs, otherwise, qemu won't work
COPY --from=builder /usr/lib/x86_64-linux-gnu/ /usr/lib/x86_64-linux-gnu/

SHELL ["/bin/bash", "-c"]
WORKDIR /home/s2e/s2e
RUN source s2e_activate
WORKDIR /home/s2e
