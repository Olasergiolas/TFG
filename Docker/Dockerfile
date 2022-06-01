FROM ubuntu:focal

LABEL description="Docker container meant to be used as a work environment for multi-arch Fuzzing."
LABEL maintainer="sergiogc5@correo.ugr.es"
LABEL url="https://github.com/Olasergiolas/TFG"

# AFL++ dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install git build-essential python3-dev \
    automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools ninja-build gcc-9-plugin-dev libstdc++-9-dev wget curl
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git

# Our dependencies
WORKDIR /tmp
RUN git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make && make install
RUN wget https://github.com/go-task/task/releases/download/v3.12.1/task_linux_amd64.deb
RUN apt-get update && apt-get install -y gdb-multiarch gcc-mipsel-linux-gnu gcc-arm-linux-gnueabi qemu-user qemu-system-arm \
    openssh-client ./task_linux_amd64.deb

# Build QEMU
WORKDIR /AFLplusplus
RUN make distrib
WORKDIR /AFLplusplus/qemu_mode
RUN CPU_TARGET=mipsel ./build_qemu_support.sh

# Needed for cJSON
RUN ln -s /usr/mipsel-linux-gnu/lib/libc-2.30.so /usr/mipsel-linux-gnu/lib/libc.so.0

RUN useradd --create-home --shell /bin/bash afl
USER afl

ENV PATH="/home/afl/.local/bin:${PATH}"
RUN wget -q -O- https://bootstrap.pypa.io/get-pip.py | python

RUN mkdir /home/afl/dependencies
WORKDIR /home/afl/dependencies

RUN git clone https://github.com/AFLplusplus/unicornafl.git
WORKDIR unicornafl
RUN git submodule update --init --recursive
#RUN python -m pip install -e ./unicorn/bindings/python
RUN python -m pip install -e ./bindings/python

RUN wget -O qiling.zip https://github.com/qilingframework/qiling/archive/refs/heads/dev.zip
RUN pip install --ignore-installed ./qiling.zip

RUN pip install requests

WORKDIR /src