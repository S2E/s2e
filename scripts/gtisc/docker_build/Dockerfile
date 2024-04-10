FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt update
RUN apt install -y --fix-missing qemu qemu-kvm

RUN apt install -y git curl wget lsb-release sudo gcc python3 python3-dev python3-venv python3-pip
RUN useradd -m s2e && echo "s2e:s2e" | chpasswd && adduser s2e sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN apt install python-is-python3

USER s2e
WORKDIR /home/s2e

RUN git clone https://github.com/GTISC/s2e-env.git
WORKDIR /home/s2e/s2e-env

ENV PATH=$PATH:/home/s2e/.local/bin
RUN pip install --upgrade pip
RUN pip install .

ARG TARGET_BRANCH=master
RUN s2e init /home/s2e/s2e -sb $TARGET_BRANCH

WORKDIR /home/s2e/s2e
SHELL ["/bin/bash", "-c"]
RUN source s2e_activate
RUN s2e update
RUN s2e build
ENV TERM=xterm-256color

WORKDIR /home/s2e